"""C2 — LLM + ZAP output. The DAST scanner-assisted (triage) condition.

Mirror of C1 on the dynamic side: ZAP runs first (same as B2), and the model
is shown each group of alerts (grouped by URL endpoint) with the attack evidence
ZAP collected and asked to confirm, downgrade, or reject them, and to add
anything ZAP missed at the same endpoint. Grouping by endpoint keeps the
model's context local to one web resource at a time.

The two phases are split via :class:`TriageCondition` (``scan_out`` / ``scan_in``).
For C2 this is what makes a large local model usable at all on a 16 GB machine:
the ZAP scan needs the Dockerized app + ZAP daemon (~7-8 GB of VM) resident,
while a 14B model needs ~10 GB — they cannot coexist. Scan with the stack up
(``--scan-out alerts.json``), tear Docker down, then triage with the full machine
free (``--scan-in alerts.json``). Triage runs purely on the saved findings, which
already carry ZAP's attack/evidence/risk in :attr:`Finding.extra`, so no running
app is needed in phase 2.
"""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from ..corpus import Target
from ..models import Usage
from ..schema import Finding
from .b2_zap import ZAP_KNOBS, _run_zap_from_config
from .base import ConditionContext, ConditionResult, TriageCondition
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings


class C2LLMZap(TriageCondition):
    id = "C2"
    label = "LLM + ZAP output (scanner-assisted DAST triage)"
    needs_model = True
    knobs = ZAP_KNOBS

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        super().validate(target, ctx)
        # The scan phase needs the running app; triage-only (scan_in) does not.
        if not self.cfg(ctx, "scan_in") and not target.base_url:
            raise ValueError(
                f"C2 needs target.base_url (the running app); {target.name} has none. "
                "Deploy the target first (see deploy/)."
            )

    def scan(self, target: Target, ctx: ConditionContext) -> tuple[list[Finding], dict]:
        zap_result = _run_zap_from_config(self, target, ctx)
        trace = {
            **zap_result.trace,
            "zap_version": zap_result.version,
            "zap_raw_findings": len(zap_result.findings),
        }
        return zap_result.findings, trace

    def triage(
        self, scanner_findings: list[Finding], target: Target, ctx: ConditionContext
    ) -> ConditionResult:
        assert ctx.model is not None

        # Group findings by endpoint URL (path only, no query params) so the
        # model sees all attacks against the same web resource at once.
        by_endpoint: dict[str, list[Finding]] = defaultdict(list)
        for f in scanner_findings:
            by_endpoint[_endpoint_key(f.location.url or "")].append(f)

        findings: list[Finding] = []
        usage = Usage()
        for endpoint_key, group in by_endpoint.items():
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _triage_prompt(endpoint_key, group)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            findings.extend(parse_findings(completion.text, self.id))

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "model": ctx.model.name,
                "endpoints_reviewed": len(by_endpoint),
            },
        )


def _endpoint_key(url: str) -> str:
    """Return scheme+host+path (no query params) as the grouping key."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")


def _triage_prompt(endpoint: str, findings: list[Finding]) -> str:
    method = (findings[0].location.method or "GET").upper() if findings else "GET"
    listed = "\n".join(
        f"- CWE-{f.vuln_class} ({f.message or 'Unknown'}) "
        f"via param {f.location.param!r}, risk {f.extra.get('risk') or '?'}\n"
        f"  Attack: {f.extra.get('attack') or ''!r}\n"
        f"  Evidence: {f.extra.get('evidence') or 'none'}"
        for f in findings
    )
    return (
        "ZAP (DAST) flagged the following potential vulnerabilities at this endpoint. "
        "For each, decide whether it is a real vulnerability (confirmed), "
        "plausible but unverified (candidate), or a false positive "
        "(not_supported). Also report any genuine vulnerability at the same "
        "endpoint that ZAP missed.\n\n"
        f"Endpoint: {method} {endpoint}\n\n"
        f"ZAP findings:\n{listed}\n\n"
        f"{OUTPUT_CONTRACT}"
    )
