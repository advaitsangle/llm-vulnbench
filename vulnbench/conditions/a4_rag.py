"""A4 — Retrieval-augmented CWE context. The model reads reference material with the file.

Prompt-level augmentation: B3 asks a cold model for a verdict; A4 first retrieves the
entries of a CWE knowledge base (:mod:`cwe_kb`) most similar to the file and prepends
them to the user turn. Everything else — system prompt, output contract, per-file loop,
scoring — is B3's, so any difference in the scorecard is attributable to the retrieved
context alone. In particular the contract still lists all eleven scored CWEs, so
retrieval adds knowledge rather than narrowing the label set: a bad retrieval degrades
the context, it does not make a case unscoreable.

The query is the file text B3 itself sends, unmodified. That includes the ``@WebServlet``
path segment BenchmarkJava leaks the ground-truth category into, so retrieval is easier
here than it would be on real code — kept anyway, because A4 reading a different corpus
than its siblings would cost the comparison the condition exists to make.
``top1_leak_match_frac`` measures the size of that effect rather than leaving it to
speculation.

``k`` is the ablation: at ``k = len(KB)`` every entry is shown and retrieval no longer
selects anything, which separates "the CWE reference helped" from "retrieving the right
part of it helped".

Its default is 5 rather than 3 on measured grounds, and for robustness across
retrievers. Over a 120-file seeded sample of BenchmarkJava the default embedding
retriever reaches the true CWE at k=3 for 98.3% of files, but the lexical fallback only
manages 78.3%; at k=5 they are 100% and 98.3%. Since ``auto`` silently falls back when
no embedding server is up, k=5 is what keeps a fallback run from quietly handing the
model the wrong weakness on a fifth of the corpus. It costs roughly 2k tokens of
reference per file. See :mod:`cwe_kb` for the full retriever comparison.
"""

from __future__ import annotations

from typing import Any

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from . import cwe_kb
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)


class A4RAGContext(Condition):
    id = "A4"
    label = "Retrieval-augmented CWE context"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("k", "int", 5,
             help=f"CWE entries retrieved per file (1-{len(cwe_kb.KB)}; "
                  f"{len(cwe_kb.KB)} = show the whole base, i.e. no retrieval)"),
        Knob("retriever", "str", "auto", choices=("auto", "embedding", "lexical"),
             help="how entries are ranked; auto prefers embeddings, falls back to lexical"),
        Knob("embed_model", "str", cwe_kb.DEFAULT_EMBED_MODEL,
             help="Ollama embedding model used by the embedding retriever"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        # Floor of 1: A4 with zero retrieved entries is B3, and a condition that can
        # be configured into being another one reports under the wrong name.
        k = max(1, min(int(self.cfg(ctx, "k")), len(cwe_kb.KB)))
        retriever = cwe_kb.build_retriever(
            str(self.cfg(ctx, "retriever")), str(self.cfg(ctx, "embed_model"))
        )

        # --sample overrides max_files: the smoke slice *is* the file set.
        paths = sampled_paths_for(self, ctx, target.source_path)
        if paths is None:
            paths = iter_source_files(target.source_path, max_files)

        # Phase 1 — read every file and retrieve for all of them, then hand the
        # embedding model's memory back before the judge loads. See
        # :meth:`cwe_kb.EmbeddingRetriever.rank_all` for why this is split.
        scored_cases: set[str] = set()
        truncated: list[str] = []
        docs: list[tuple[str, str]] = []
        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the model finds nothing in it
            code, was_truncated = read_capped(path, max_bytes)
            if not code:
                continue
            if was_truncated:
                truncated.append(path)
            docs.append((path, code))

        retrieved = retriever.rank_all([code for _, code in docs], k)
        retriever.release()

        # Phase 2 — judge each file against the context retrieved for it.
        findings: list[Finding] = []
        usage = Usage()
        leaked_files = leak_matches = echoed_top1 = 0
        for (path, code), entries in zip(docs, retrieved, strict=True):
            leaked = cwe_kb.leaked_category(code)
            if leaked is not None:
                leaked_files += 1
                leak_matches += entries[0].benchmark_category == leaked

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(path, code, entries)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                # Pin the location to the file we actually scanned.
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                f.extra = {**f.extra, "retrieved_cwes": [e.cwe for e in entries]}
                echoed_top1 += f.vuln_class == entries[0].cwe
                findings.append(f)

        trace: dict[str, Any] = {
            "files_scanned": len(docs),
            "model": ctx.model.name,
            "truncated_files": len(truncated),
            "max_file_bytes": max_bytes,
            "retriever": retriever.name,  # post-fallback, so the record says what ran
            "k": k,                       # post-clamp, likewise
            # How often the top hit merely echoed the category the corpus leaks:
            # the honest size of the annotation leak for this condition.
            "top1_leak_matches": leak_matches,
            "leak_annotated_files": leaked_files,
            "top1_leak_match_frac": (
                round(leak_matches / leaked_files, 3) if leaked_files else 0.0
            ),
            # Anchoring: how often the model simply reported the CWE retrieval ranked
            # first. A high value means the ranking is acting as the verdict rather
            # than as reference material — the failure A1's scout hint showed.
            "findings_echoing_top1": echoed_top1,
            "findings_echoing_top1_frac": (
                round(echoed_top1 / len(findings), 3) if findings else 0.0
            ),
        }
        return ConditionResult(
            findings=findings,
            # Retrieval's own tokens and seconds count against A4, not against nobody.
            usage=usage + retriever.usage,
            trace=trace,
            # Score only over what we actually looked at (respects max_files).
            scored_cases=scored_cases or None,
        )


def _user_prompt(path: str, code: str, entries: list[cwe_kb.CWEEntry]) -> str:
    return (
        f"{cwe_kb.render_context(entries)}\n\n"
        f"Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )
