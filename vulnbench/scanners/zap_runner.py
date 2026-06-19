"""Drive OWASP ZAP and normalize its alerts to :class:`Finding`.

ZAP is the primary DAST tool (``claude.md``): free, scriptable over a REST API in
daemon mode, and the OWASP Benchmark ships a ZAP scorecard generator, so a ZAP run
is scorable against the *same* ground truth as Semgrep. That shared-ground-truth
property is the whole point of the B2 (and later C2) cell.

This module talks to an already-running ZAP daemon over HTTP using only the
standard library (the harness stays dependency-free; deploying ZAP itself is a
Docker concern handled in ``deploy/``).

Two scan flows:

* **Spidered** (default): ``spider(base_url) -> active-scan -> alerts``. Fine for
  realistic apps whose links a crawler can discover.
* **Seeded**: the caller supplies the exact requests to test (method, URL, params,
  headers, cookies); each is replayed through ZAP so it lands in ZAP's Sites tree,
  then a single recursive active-scan attacks them. This is required for the OWASP
  Benchmark, whose injection points live in form params, query params, headers and
  cookies that a blind spider cannot discover — exactly what BenchmarkUtils' own
  crawler does before handing off to ZAP.

Each ZAP alert carries a ``cweid``, the offending ``url``/``method``/``param`` and
a risk/confidence label; we map those onto an ENDPOINT-kind :class:`Finding`. On
the deployed Benchmark the test-case id lives in the URL, so these findings score
through :meth:`Finding.benchmark_test_case` with no extra mapping.

The parser (:func:`findings_from_zap_alerts`) is split out so it is unit-testable
on recorded alert JSON without a live ZAP.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from ..schema import Finding, Location

#: Default ZAP daemon address (``zap.sh -daemon -port 8090``). Override per run.
DEFAULT_ZAP_URL = "http://127.0.0.1:8090"


def _parse_cwe(value: object) -> int:
    """ZAP reports ``cweid`` as a string; ``"-1"``/missing means unmapped."""
    try:
        cwe = int(str(value).strip())
    except (TypeError, ValueError):
        return 0
    return cwe if cwe > 0 else 0


#: ZAP confidence labels -> a number in [0, 1], matching the Semgrep runner's
#: scale so confidences are comparable across SAST and DAST findings.
_CONFIDENCE = {
    "false positive": 0.1,
    "low": 0.3,
    "medium": 0.6,
    "high": 0.9,
    "confirmed": 1.0,
}


def _confidence(label: object) -> float:
    return _CONFIDENCE.get(str(label).strip().lower(), 0.7)


def findings_from_zap_alerts(alerts: list[dict], source_condition: str = "B2") -> list[Finding]:
    """Convert ZAP ``core/view/alerts`` records into normalized findings.

    One :class:`Finding` per alert instance (ZAP already emits one record per
    offending request), located at the ENDPOINT it fired on.
    """
    findings: list[Finding] = []
    for a in alerts:
        name = (a.get("alert") or a.get("name") or "").strip()
        desc = (a.get("description") or "").strip()
        message = f"{name}: {desc}" if name and desc else (name or desc or None)
        findings.append(
            Finding(
                vuln_class=_parse_cwe(a.get("cweid")),
                location=Location.endpoint(
                    url=a.get("url", ""),
                    method=a.get("method") or None,
                    param=a.get("param") or None,
                ),
                source_condition=source_condition,
                confidence=_confidence(a.get("confidence")),
                rule_id=str(a.get("pluginId")) if a.get("pluginId") else None,
                message=message,
                extra={
                    "risk": a.get("risk"),
                    "attack": a.get("attack"),
                    "evidence": a.get("evidence"),
                },
            )
        )
    return findings


@dataclass
class SeedRequest:
    """One HTTP request to replay into ZAP so its inputs become scan targets.

    ``params`` are query-string params; ``form`` makes the request a POST with a
    urlencoded body. Both, plus ``headers`` and ``cookies``, become injection
    points the active scanner attacks.
    """

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def to_raw(self) -> str:
        """Render the full raw HTTP request ZAP's ``sendRequest`` expects.

        Uses an absolute-URI request line so ZAP infers scheme (http/https)
        unambiguously, and always sends a ``Host`` header.
        """
        url = self.url
        if self.params:
            sep = "&" if urllib.parse.urlsplit(url).query else "?"
            url = f"{url}{sep}{urllib.parse.urlencode(self.params)}"
        body = urllib.parse.urlencode(self.form) if self.form else ""

        headers = dict(self.headers)
        headers.setdefault("Host", urllib.parse.urlsplit(url).netloc)
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if body:
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            headers["Content-Length"] = str(len(body.encode("utf-8")))

        lines = [f"{self.method} {url} HTTP/1.1"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        return "\r\n".join(lines) + "\r\n\r\n" + body


@dataclass
class ZapResult:
    """Raw + normalized output of one ZAP scan."""

    findings: list[Finding]
    raw_alerts: list[dict] = field(default_factory=list)
    version: str | None = None  # ZAP version, for scorecard provenance
    trace: dict = field(default_factory=dict)  # per-phase step log


class ZapError(RuntimeError):
    """A ZAP REST call failed or a scan phase timed out."""


class ZapClient:
    """Thin stdlib HTTP wrapper over the ZAP REST API (daemon mode).

    Only the handful of endpoints the B2 flow needs are exposed. Views/most
    actions are simple GETs; ``sendRequest`` carries a full raw request so it is
    POSTed to avoid URL-length limits.
    """

    def __init__(self, zap_url: str = DEFAULT_ZAP_URL, api_key: str = "", timeout: float = 30.0):
        self.zap_url = zap_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _endpoint(self, component: str, kind: str, name: str) -> str:
        return f"{self.zap_url}/JSON/{component}/{kind}/{name}/"

    def _request(self, url: str, data: bytes | None = None) -> dict:
        try:
            with urllib.request.urlopen(url, data=data, timeout=self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise ZapError(
                f"could not reach ZAP at {self.zap_url} ({exc}). Start it with "
                f"`zap.sh -daemon -port <port>` or the deploy/ Docker setup, and "
                f"pass --config '{{\"zap_url\": \"...\"}}' if it is elsewhere."
            ) from exc

    def _call(self, component: str, kind: str, name: str, **params: object) -> dict:
        """GET form of an API call (views and lightweight actions)."""
        if self.api_key:
            params.setdefault("apikey", self.api_key)
        query = urllib.parse.urlencode({k: str(v) for k, v in params.items()})
        return self._request(f"{self._endpoint(component, kind, name)}?{query}")

    def _post(self, component: str, kind: str, name: str, **params: object) -> dict:
        """POST form of an API call (for large payloads like sendRequest)."""
        if self.api_key:
            params.setdefault("apikey", self.api_key)
        data = urllib.parse.urlencode({k: str(v) for k, v in params.items()}).encode("utf-8")
        return self._request(self._endpoint(component, kind, name), data=data)

    def version(self) -> str | None:
        return self._call("core", "view", "version").get("version")

    def send_request(self, raw_request: str, follow_redirects: bool = True) -> dict:
        """Replay a raw HTTP request through ZAP, recording it in the Sites tree."""
        return self._post(
            "core", "action", "sendRequest",
            request=raw_request, followRedirects=str(follow_redirects).lower(),
        )

    def spider(self, base_url: str) -> str:
        return self._call("spider", "action", "scan", url=base_url).get("scan", "0")

    def spider_status(self, scan_id: str) -> int:
        return int(self._call("spider", "view", "status", scanId=scan_id).get("status", 0))

    def disable_scanners(self, ids: list[str]) -> dict:
        """Turn off specific active-scan rules by plugin id (scan-policy tuning)."""
        return self._call("ascan", "action", "disableScanners", ids=",".join(ids))

    def active_scan(self, base_url: str, recurse: bool = True) -> str:
        return self._call(
            "ascan", "action", "scan", url=base_url, recurse=str(recurse).lower()
        ).get("scan", "0")

    def active_scan_status(self, scan_id: str) -> int:
        return int(self._call("ascan", "view", "status", scanId=scan_id).get("status", 0))

    def alerts(self, base_url: str, start: int = 0, count: int = 0) -> list[dict]:
        return self._call(
            "core", "view", "alerts", baseurl=base_url, start=start, count=count
        ).get("alerts", [])


def _await(poll, label: str, poll_interval: float, max_wait: float) -> None:
    """Block until ``poll()`` returns 100 (%) or raise on timeout."""
    deadline = time.monotonic() + max_wait
    while True:
        if poll() >= 100:
            return
        if time.monotonic() >= deadline:
            raise ZapError(f"{label} did not finish within {max_wait:.0f}s")
        time.sleep(poll_interval)


def run_zap(
    base_url: str,
    *,
    zap_url: str = DEFAULT_ZAP_URL,
    api_key: str = "",
    recurse: bool = True,
    poll_interval: float = 3.0,
    max_wait: float = 1800.0,
    source_condition: str = "B2",
    seed_requests: list[SeedRequest] | None = None,
    disable_scanners: list[str] | None = None,
    client: ZapClient | None = None,
) -> ZapResult:
    """Scan ``base_url`` and return normalized findings.

    With ``seed_requests`` the flow is seed-then-attack (each request is replayed
    into ZAP, then one recursive active-scan covers them); without, it spiders
    first. ``disable_scanners`` turns off active-scan rules by plugin id before
    scanning (e.g. the browser-based DOM XSS rule, which is memory-heavy and
    irrelevant to server-side targets). ``client`` is injectable so tests can
    drive the flow with a fake. ``max_wait`` bounds each scan phase independently.
    """
    zap = client or ZapClient(zap_url, api_key)
    version = zap.version()
    trace: dict = {"zap_url": zap_url, "base_url": base_url}

    if disable_scanners:
        zap.disable_scanners(disable_scanners)
        trace["disabled_scanners"] = disable_scanners

    if seed_requests:
        for req in seed_requests:
            zap.send_request(req.to_raw())
        trace["seeded_requests"] = len(seed_requests)
    else:
        spider_id = zap.spider(base_url)
        _await(lambda: zap.spider_status(spider_id), "spider", poll_interval, max_wait)
        trace["spider_id"] = spider_id

    ascan_id = zap.active_scan(base_url, recurse=recurse)
    _await(lambda: zap.active_scan_status(ascan_id), "active scan", poll_interval, max_wait)

    alerts = zap.alerts(base_url)
    trace["ascan_id"] = ascan_id
    trace["alert_count"] = len(alerts)
    return ZapResult(
        findings=findings_from_zap_alerts(alerts, source_condition),
        raw_alerts=alerts,
        version=version,
        trace=trace,
    )
