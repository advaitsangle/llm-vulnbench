"""Turn the OWASP Benchmark crawler manifest into ZAP seed requests.

The Benchmark ships ``data/benchmark-crawler-http.xml`` listing, for every test
case, the exact request that exercises its (possibly vulnerable) input — the
method is implied by where the input lives:

    <benchmarkTest URL="https://localhost:8443/benchmark/sqli-00/BenchmarkTest00026" ...>
        <getparam name="username" value="" />          # query string  -> GET
        <formparam name="BenchmarkTest00026" value="bar" />  # body     -> POST
        <header name="Referer" value="SafeText" />     # request header
        <cookie name="BenchmarkTest00001" value="FileName" />
    </benchmarkTest>

These inputs are not discoverable by a blind spider (see ``zap_runner``), so we
parse them into :class:`SeedRequest` objects and replay them into ZAP before the
active scan. A test case with any ``formparam`` is a POST; otherwise a GET.

The manifest hard-codes ``https://localhost:8443``; pass ``base_url`` to retarget
the requests at wherever the app is actually deployed (e.g. the in-Docker host
``https://benchmark:8443``).
"""

from __future__ import annotations

import urllib.parse
from xml.etree import ElementTree as ET

from .zap_runner import SeedRequest


def _retarget(url: str, base_url: str | None) -> str:
    """Replace the scheme+host of ``url`` with those of ``base_url``."""
    if not base_url:
        return url
    base = urllib.parse.urlsplit(base_url)
    return urllib.parse.urlunsplit(urllib.parse.urlsplit(url)._replace(
        scheme=base.scheme, netloc=base.netloc
    ))


def load_crawler_requests(
    xml_path: str, base_url: str | None = None, limit: int | None = None
) -> list[SeedRequest]:
    """Parse the crawler XML into seed requests, optionally capped at ``limit``.

    ``limit`` seeds only the first N cases — handy for a quick partial scan when
    the full ~2740-case active scan is too slow to wait on.
    """
    root = ET.parse(xml_path).getroot()
    requests: list[SeedRequest] = []
    for test in root.findall("benchmarkTest"):
        url = _retarget(test.get("URL", ""), base_url)
        params = {e.get("name", ""): e.get("value", "") for e in test.findall("getparam")}
        form = {e.get("name", ""): e.get("value", "") for e in test.findall("formparam")}
        headers = {e.get("name", ""): e.get("value", "") for e in test.findall("header")}
        cookies = {e.get("name", ""): e.get("value", "") for e in test.findall("cookie")}
        requests.append(
            SeedRequest(
                url=url,
                method="POST" if form else "GET",
                params=params,
                form=form,
                headers=headers,
                cookies=cookies,
            )
        )
        if limit is not None and len(requests) >= limit:
            break
    return requests
