"""The condition ladder. Each cell of the evaluation matrix is one Condition.

Registry maps the ids used in the proposal to classes:

    B1  Semgrep only                 (SAST baseline)        [implemented]
    B2  OWASP ZAP only               (DAST baseline)        [implemented]
    B3  LLM only                     (unaided model)        [implemented]
    C1  LLM + Semgrep output         (scanner-assisted)     [implemented]
    C2  LLM + ZAP output             (scanner-assisted)     [implemented]
    C3  LLM-authored Semgrep rules   (LLM improves tool)    [implemented]
    A1  Multi-agent roles            (scout/hunt/verify)    [implemented]
    A2  AST-augmented context        (structural context)   [implemented]
    A3  CFG/DFG-augmented context    (structural context)   [implemented]
    A5  Risky-portion extraction     (reduce, then B3)      [implemented]
    A7  Few-shot labeled examples                           [implemented]
    A8  Chain-of-thought (reason before verdict)            [implemented]
"""

from __future__ import annotations

from .a1_agents import A1MultiAgent
from .a2_ast_context import A2ASTContext
from .a3_cfg_dfg_context import A3CFGDFGContext
from .a5_parse import A5Parse
from .a7_fewshot import A7FewShot
from .a8_cot import A8ChainOfThought
from .b1_semgrep import B1Semgrep
from .b2_zap import B2Zap
from .b3_llm import B3LLM
from .base import Condition, ConditionContext, ConditionResult, Knob, KnobType
from .c1_llm_semgrep import C1LLMSemgrep
from .c2_llm_zap import C2LLMZap
from .c3_llm_rules import C3LLMRules

REGISTRY: dict[str, type[Condition]] = {
    "B1": B1Semgrep,
    "B2": B2Zap,
    "B3": B3LLM,
    "C1": C1LLMSemgrep,
    "C2": C2LLMZap,
    "C3": C3LLMRules,
    "A1": A1MultiAgent,
    "A2": A2ASTContext,
    "A3": A3CFGDFGContext,
    "A5": A5Parse,
    "A7": A7FewShot,
    "A8": A8ChainOfThought,
}


def get_condition(condition_id: str) -> type[Condition]:
    try:
        return REGISTRY[condition_id.upper()]
    except KeyError:
        raise KeyError(
            f"Unknown condition {condition_id!r}. Known: {', '.join(sorted(REGISTRY))}"
        ) from None


__all__ = [
    "Condition",
    "ConditionContext",
    "ConditionResult",
    "Knob",
    "KnobType",
    "REGISTRY",
    "get_condition",
    "A7FewShot",
    "A8ChainOfThought",
]
