"""B2 — OWASP ZAP only. The DAST baseline.

Mirror image of B1 on the dynamic side: instead of reading source, ZAP attacks the
*running* application and reports what responded like a vulnerability. It needs
``target.base_url`` (the deployed app) and a reachable ZAP daemon; ``deploy/``
brings both up in Docker. Connection knobs are declared as :data:`ZAP_KNOBS` (and
shared with C2) so scored runs stay reproducible.
"""

from __future__ import annotations

from ..corpus import Target
from ..scanners.benchmark_crawl import load_crawler_requests
from ..scanners.zap_runner import DEFAULT_ZAP_URL, run_zap
from .base import Condition, ConditionContext, ConditionResult, Knob

#: Everything needed to drive a ZAP scan. Shared verbatim by B2 (scan only) and C2
#: (scan then triage), which is why they live here rather than on either condition.
ZAP_KNOBS = (
    Knob("zap_url", "str", DEFAULT_ZAP_URL, help="address of the ZAP daemon"),
    Knob("zap_api_key", "str", "", help="ZAP API key (empty = disabled)"),
    Knob("zap_recurse", "bool", True, help="recurse into discovered URLs during the scan"),
    Knob("zap_max_wait", "float", 1800.0, help="per-phase timeout, in seconds"),
    Knob("zap_seed_crawler", "path", None,
         help="Benchmark crawler XML; seeds ZAP with each case's exact request instead "
              "of spidering (required for fair OWASP Benchmark scores)"),
    Knob("zap_seed_limit", "int", None, help="cap the number of seeded cases (quick scans)"),
    Knob("zap_disable_scanners", "list", ["40026"], advanced=True,
         help="active-scan plugin ids to skip; the default drops the browser-based "
              "DOM-XSS rule (memory-heavy, irrelevant to server-side cases)"),
)


def _run_zap_from_config(condition: Condition, target: Target, ctx: ConditionContext):
    """Drive ZAP against ``target`` using the condition's :data:`ZAP_KNOBS` values."""
    seed_crawler = condition.cfg(ctx, "zap_seed_crawler")
    seed_requests = None
    if seed_crawler:
        limit = condition.cfg(ctx, "zap_seed_limit")
        seed_requests = load_crawler_requests(
            seed_crawler,
            base_url=target.base_url,
            limit=int(limit) if limit is not None else None,
        )

    return run_zap(
        target.base_url,
        zap_url=condition.cfg(ctx, "zap_url"),
        api_key=condition.cfg(ctx, "zap_api_key"),
        recurse=bool(condition.cfg(ctx, "zap_recurse")),
        max_wait=float(condition.cfg(ctx, "zap_max_wait")),
        source_condition=condition.id,
        seed_requests=seed_requests,
        disable_scanners=condition.cfg(ctx, "zap_disable_scanners"),
    )


class B2Zap(Condition):
    id = "B2"
    label = "OWASP ZAP only (DAST baseline)"
    needs_model = False
    needs_url = True
    knobs = ZAP_KNOBS

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        result = _run_zap_from_config(self, target, ctx)
        return ConditionResult(
            findings=result.findings,
            trace={**result.trace, "zap_version": result.version},
        )
