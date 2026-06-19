"""B2 — OWASP ZAP only. The DAST baseline.

Mirror image of B1 on the dynamic side: instead of reading source, ZAP attacks the
*running* application and reports what responded like a vulnerability. It needs
``target.base_url`` (the deployed app) and a reachable ZAP daemon; ``deploy/``
brings both up in Docker. Connection knobs come from ``ctx.config`` so scored runs
stay reproducible:

    zap_url       ZAP daemon address        (default http://127.0.0.1:8090)
    zap_api_key   ZAP API key               (default "", i.e. disabled)
    zap_recurse   recurse during scan       (default True)
    zap_max_wait  per-phase timeout secs    (default 1800)
    zap_seed_crawler  path to a Benchmark crawler XML; when set, ZAP is seeded
                      with each test case's exact request instead of spidering
                      (required for fair OWASP Benchmark scores — see
                      ``scanners.benchmark_crawl`` and ``zap_runner``).
    zap_seed_limit    cap the number of seeded cases (partial/quick scans)
    zap_disable_scanners  list of active-scan plugin ids to skip (default
                      ["40026"], the browser-based DOM-XSS rule: memory-heavy and
                      irrelevant to server-side Benchmark cases). Pass [] to keep
                      every rule.
"""

from __future__ import annotations

from ..corpus import Target
from ..scanners.benchmark_crawl import load_crawler_requests
from ..scanners.zap_runner import DEFAULT_ZAP_URL, run_zap
from .base import Condition, ConditionContext, ConditionResult


class B2Zap(Condition):
    id = "B2"
    label = "OWASP ZAP only (DAST baseline)"
    needs_model = False

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        super().validate(target, ctx)
        if not target.base_url:
            raise ValueError(
                f"B2 needs target.base_url (the running app); {target.name} has none. "
                "Deploy the target first (see deploy/)."
            )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        seed_crawler = ctx.config.get("zap_seed_crawler")
        seed_requests = None
        if seed_crawler:
            limit = ctx.config.get("zap_seed_limit")
            seed_requests = load_crawler_requests(
                seed_crawler,
                base_url=target.base_url,
                limit=int(limit) if limit is not None else None,
            )

        result = run_zap(
            target.base_url,
            zap_url=ctx.config.get("zap_url", DEFAULT_ZAP_URL),
            api_key=ctx.config.get("zap_api_key", ""),
            recurse=bool(ctx.config.get("zap_recurse", True)),
            max_wait=float(ctx.config.get("zap_max_wait", 1800.0)),
            source_condition=self.id,
            seed_requests=seed_requests,
            disable_scanners=ctx.config.get("zap_disable_scanners", ["40026"]),
        )
        return ConditionResult(
            findings=result.findings,
            trace={**result.trace, "zap_version": result.version},
        )
