"""A4 — retrieval-augmented CWE context.

Runs fully offline: the judge is a message-recording backend and the retriever is
pinned to the stdlib lexical one, so prompt *shape* and retrieval *ranking* are both
asserted directly rather than inferred from counters. The embedding path is covered
by stubbing the HTTP call, never by contacting a daemon.
"""

from __future__ import annotations

import json
import re

from vulnbench.conditions import cwe_kb
from vulnbench.conditions.a4_rag import A4RAGContext
from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models.base import Completion, ModelBackend, Usage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SQLI = (
    '@WebServlet(value = "/sqli-00/BenchmarkTest00001")\n'
    "public class BenchmarkTest00001 extends HttpServlet {\n"
    '  String q = "SELECT * FROM users WHERE id=" + request.getParameter("id");\n'
    "  Statement st = connection.createStatement();\n"
    "  st.executeQuery(q);\n"
    "}\n"
)

_SAFE = (
    '@WebServlet(value = "/sqli-00/BenchmarkTest00002")\n'
    "public class BenchmarkTest00002 extends HttpServlet {\n"
    "  int x = 1 + 1;\n"
    "}\n"
)


def _benchmark(tmp_path):
    """Two-file OWASP-Benchmark-style fixture."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text(_SQLI)
    (src / "BenchmarkTest00002.java").write_text(_SAFE)
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    return Target("fix", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


_FINDING_REPLY = json.dumps({
    "findings": [{
        "cwe": 89,
        "vuln_type": "SQL Injection",
        "diagnostic": "param into SQL",
        "file": None,
        "line": 3,
        "url": None,
        "param": "id",
        "verdict": "confirmed",
        "confidence": 0.9,
        "evidence": "concat",
        "counter_evidence": None,
        "remediation": "use PreparedStatement",
        "requires_human_review": False,
    }]
})

_EMPTY_REPLY = json.dumps({"findings": []})

#: Every A4 run in this file uses the deterministic stdlib retriever.
_LEXICAL = {"retriever": "lexical"}

#: Each retrieved entry opens with its own `CWE-<id> — <name>` header. The output
#: contract also names CWE ids, but as bare numbers, so this counts entries only.
_ENTRY_HEADER = re.compile(r"^CWE-\d+ — ", re.M)


def _entries_shown(content: str) -> int:
    return len(_ENTRY_HEADER.findall(content))


def _stub_embedding(monkeypatch, log: list | None = None):
    """Drive the embedding retriever offline by replacing its only HTTP seam.

    Returns one unit vector per input so batch sizes stay self-consistent, and
    records the call order when ``log`` is given.
    """
    def fake_embed(self, inputs):
        if log is not None:
            log.append(("embed", len(inputs)))
        self.usage = self.usage + Usage(input_tokens=10, seconds=0.25)
        return [[1.0, 0.0]] * len(inputs)

    def fake_post(self, payload):
        if log is not None:
            log.append(("release", payload.get("keep_alive")))
        return {}

    monkeypatch.setattr(cwe_kb.EmbeddingRetriever, "_embed", fake_embed)
    monkeypatch.setattr(cwe_kb.EmbeddingRetriever, "_post", fake_post)


class RecordingBackend(ModelBackend):
    """Captures the message list passed to complete(). Scripted per call."""

    def __init__(self, replies: list[str] | None = None) -> None:
        self.name = "mock-recording"
        self._replies = list(replies or [])
        self._call_idx = 0
        self.calls: list[list[dict]] = []

    def _complete(self, messages, tools=None, **kwargs):
        self.calls.append(list(messages))
        if self._replies:
            text = self._replies[self._call_idx % len(self._replies)]
            self._call_idx += 1
        else:
            text = _EMPTY_REPLY
        return Completion(text=text, usage=Usage())


# ---------------------------------------------------------------------------
# The knowledge base
# ---------------------------------------------------------------------------

class TestKnowledgeBase:
    def test_kb_covers_exactly_the_scored_cwes(self):
        """The base must cover every CWE the output contract lets a model name.

        A CWE the contract permits but the base cannot describe would be a case A4
        can never receive context for; one in the base but not the contract would be
        context the model is forbidden to act on.
        """
        from vulnbench.conditions.llm_common import SCORED_CWES

        contract = {int(tok) for tok in SCORED_CWES.replace("|", " ").split() if tok.isdigit()}
        assert {e.cwe for e in cwe_kb.KB} == contract

    def test_every_entry_has_sourced_prose(self):
        for e in cwe_kb.KB:
            assert e.name.strip() and e.description.strip(), f"CWE-{e.cwe} is empty"
            assert e.description in e.as_context()

    def test_provenance_is_recorded(self):
        """A scorecard has to be able to name the exact CWE data the run was given."""
        for field in ("catalog", "url", "version", "catalog_date", "retrieved"):
            assert cwe_kb.SOURCE[field], f"missing provenance field {field}"
        assert cwe_kb.SOURCE["catalog"] == "MITRE CWE"

    def test_categories_are_unique_and_lowercase(self):
        cats = [e.benchmark_category for e in cwe_kb.KB]
        assert len(set(cats)) == len(cats)
        assert all(c.islower() for c in cats)

    def test_document_excludes_the_leak_diagnostic(self):
        """The indexed text is the sourced prose alone.

        The category token is corpus metadata, not knowledge; folding it into the
        document would let a query match on the corpus's leaked annotation directly.
        """
        for e in cwe_kb.KB:
            parts = [e.name, e.description, *e.mitigations]
            if e.example_code:
                parts.append(e.example_code)
            assert e.as_document() == " ".join(parts)


class TestLeakedCategory:
    def test_extracts_the_webservlet_category(self):
        assert cwe_kb.leaked_category(_SQLI) == "sqli"

    def test_none_when_the_annotation_is_absent(self):
        assert cwe_kb.leaked_category("class Foo {}") is None


class TestLexicalRetriever:
    def test_matching_cwe_is_retrieved_within_k(self):
        """The true CWE reaches the prompt at the default k.

        Deliberately not asserted at top-1. MITRE's prose is language-neutral — CWE-89
        talks about "an SQL command", never about ``executeQuery`` — so a five-line
        snippet does not rank it first, and pinning top-1 here would be a test tuned to
        one fixture. The corpus-level numbers that actually justify the default k are
        recorded in :mod:`vulnbench.conditions.cwe_kb`.
        """
        assert 89 in [e.cwe for e in cwe_kb.LexicalRetriever().top_k(_SQLI, 5)]

    def test_k_bounds_the_result(self):
        r = cwe_kb.LexicalRetriever()
        assert len(r.top_k(_SQLI, 3)) == 3
        assert len(r.top_k(_SQLI, len(cwe_kb.KB) + 5)) == len(cwe_kb.KB)

    def test_ranking_is_deterministic(self):
        """A scored row has to be re-runnable, so the same query ranks the same way."""
        a = cwe_kb.LexicalRetriever().top_k(_SQLI, len(cwe_kb.KB))
        b = cwe_kb.LexicalRetriever().top_k(_SQLI, len(cwe_kb.KB))
        assert [e.cwe for e in a] == [e.cwe for e in b]

    def test_a_query_with_no_overlap_still_returns_entries(self):
        """Zero similarity is a weak result, not an error: the model still gets context."""
        out = cwe_kb.LexicalRetriever().top_k("zzz", 2)
        assert len(out) == 2


class TestBuildRetriever:
    def test_lexical_is_selected_explicitly(self):
        assert cwe_kb.build_retriever("lexical", "unused").name == "lexical"

    def test_auto_falls_back_when_embedding_is_unavailable(self, monkeypatch):
        def boom(*args, **kwargs):
            raise cwe_kb.RetrievalError("no daemon")

        monkeypatch.setattr(cwe_kb, "EmbeddingRetriever", boom)
        assert cwe_kb.build_retriever("auto", "nomic-embed-text").name == "lexical"

    def test_explicit_embedding_does_not_silently_fall_back(self, monkeypatch):
        """Asking for embeddings and getting lexical would misreport the run."""
        def boom(*args, **kwargs):
            raise cwe_kb.RetrievalError("no daemon")

        monkeypatch.setattr(cwe_kb, "EmbeddingRetriever", boom)
        try:
            cwe_kb.build_retriever("embedding", "nomic-embed-text")
        except cwe_kb.RetrievalError:
            return
        raise AssertionError("expected RetrievalError to propagate")

    def test_unknown_mode_is_rejected(self):
        try:
            cwe_kb.build_retriever("magic", "unused")
        except ValueError as exc:
            assert "magic" in str(exc)
            return
        raise AssertionError("expected ValueError")


class TestEmbeddingRetriever:
    """Covers the dense path without contacting a daemon."""

    def _stub(self, monkeypatch, vectors_by_call):
        calls = []

        def fake_embed(self, inputs):
            calls.append(list(inputs))
            self.usage = self.usage + Usage(input_tokens=7, seconds=0.5)
            return vectors_by_call[len(calls) - 1]

        monkeypatch.setattr(cwe_kb.EmbeddingRetriever, "_embed", fake_embed)
        return calls

    def test_base_is_embedded_once_at_construction(self, monkeypatch):
        """Eleven documents cost one batched request, not one per file scanned."""
        docs = [[1.0, 0.0]] * len(cwe_kb.KB)
        calls = self._stub(monkeypatch, [docs, [[1.0, 0.0]], [[1.0, 0.0]]])
        r = cwe_kb.EmbeddingRetriever()
        assert len(calls) == 1 and len(calls[0]) == len(cwe_kb.KB)
        r.top_k("a", 1)
        r.top_k("b", 1)
        assert len(calls) == 3  # construction + one per query

    def test_ranks_by_cosine_similarity(self, monkeypatch):
        docs = [[0.0, 1.0] for _ in cwe_kb.KB]
        docs[4] = [1.0, 0.0]  # an arbitrary entry made the nearest neighbour
        self._stub(monkeypatch, [docs, [[1.0, 0.0]]])
        r = cwe_kb.EmbeddingRetriever()
        assert r.top_k("query", 1)[0].cwe == cwe_kb.KB[4].cwe

    def test_retrieval_cost_is_accumulated(self, monkeypatch):
        docs = [[1.0, 0.0]] * len(cwe_kb.KB)
        self._stub(monkeypatch, [docs, [[1.0, 0.0]]])
        r = cwe_kb.EmbeddingRetriever()
        r.top_k("query", 1)
        assert r.usage.input_tokens == 14 and r.usage.seconds == 1.0


# ---------------------------------------------------------------------------
# The condition
# ---------------------------------------------------------------------------

class TestA4Prompt:
    def test_retrieved_context_precedes_the_file(self, tmp_path):
        """One call per file: system + a single user turn carrying reference then code."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)

        assert len(backend.calls) == 2, "expected one call per file"
        msgs = backend.calls[0]
        assert [m["role"] for m in msgs] == ["system", "user"]
        content = msgs[1]["content"]
        assert content.index("CWE-") < content.index("BenchmarkTest00001.java"), (
            "the retrieved reference must come before the file"
        )

    def test_the_right_cwe_is_in_the_retrieved_block(self, tmp_path):
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)
        assert "CWE-89" in backend.calls[0][1]["content"]

    def test_output_contract_is_unchanged(self, tmp_path):
        """A4 must still offer all eleven labels; retrieval adds knowledge, not a filter.

        If the contract narrowed with k, a retrieval miss would make a case
        unscoreable and the row would measure the retriever rather than the model.
        """
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A4", model=backend, config={**_LEXICAL, "k": 1})

        content = backend.calls[0][1]["content"]
        for cwe in (e.cwe for e in cwe_kb.KB):
            assert str(cwe) in content, f"CWE {cwe} missing from the contract's label list"

    def test_query_is_the_unmodified_file(self, tmp_path):
        """A4 sends B3's file text verbatim; a different corpus would break the comparison."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)
        assert _SQLI in backend.calls[0][1]["content"]


class TestA4Knobs:
    def test_k_controls_the_number_of_entries_shown(self, tmp_path):
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(
            _benchmark(tmp_path), "A4", model=backend, config={**_LEXICAL, "k": 2}
        )
        assert _entries_shown(backend.calls[0][1]["content"]) == 2
        assert record.trace["k"] == 2

    def test_k_zero_is_clamped_to_one_entry(self, tmp_path):
        """A4 cannot be configured into being B3: zero retrieved entries floors at one."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(
            _benchmark(tmp_path), "A4", model=backend, config={**_LEXICAL, "k": 0}
        )
        assert record.trace["k"] == 1
        assert _entries_shown(backend.calls[0][1]["content"]) == 1

    def test_k_above_the_base_shows_the_whole_base(self, tmp_path):
        """The no-retrieval ablation: every entry, so ranking selects nothing."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(
            _benchmark(tmp_path), "A4", model=backend, config={**_LEXICAL, "k": 999}
        )
        assert record.trace["k"] == len(cwe_kb.KB)
        assert _entries_shown(backend.calls[0][1]["content"]) == len(cwe_kb.KB)

    def test_declared_knobs_do_not_collide_with_other_conditions(self):
        """`--config` keys are global, so A4's knobs must not set another cell's."""
        from vulnbench.conditions import get_condition

        a4 = {k.name for k in A4RAGContext.all_knobs()}
        for other in ("A7", "A8", "B3"):
            shared = a4 & {k.name for k in get_condition(other).all_knobs()}
            assert shared <= {"max_files", "max_file_bytes", "sample_files", "sample_seed"}


class TestA4Sequencing:
    """Retrieval must finish and free its model before the judge starts.

    Interleaving the two keeps both resident; on a 16 GB machine that pushes the
    judge partly onto CPU and taxes A4's latency for a reason unrelated to whether
    retrieval helps.
    """

    def test_retrieval_completes_and_releases_before_first_judge_call(
        self, tmp_path, monkeypatch
    ):
        log: list = []
        _stub_embedding(monkeypatch, log)

        class LoggingBackend(RecordingBackend):
            def _complete(self, messages, tools=None, **kwargs):
                log.append(("judge", None))
                return super()._complete(messages, tools=tools, **kwargs)

        run_one(_benchmark(tmp_path), "A4", model=LoggingBackend(),
                config={"retriever": "embedding"})

        kinds = [k for k, _ in log]
        assert "judge" in kinds and "release" in kinds
        assert kinds.index("release") < kinds.index("judge"), (
            f"embedding model must be released before judging; got {kinds}"
        )
        assert kinds.index("release") == max(
            i for i, k in enumerate(kinds) if k == "embed"
        ) + 1, "every embed must happen before the release"

    def test_queries_are_batched_not_one_call_per_file(self, tmp_path, monkeypatch):
        log: list = []
        _stub_embedding(monkeypatch, log)
        run_one(_benchmark(tmp_path), "A4", model=RecordingBackend(),
                config={"retriever": "embedding"})

        embeds = [n for k, n in log if k == "embed"]
        # One request for the 11-entry base, one covering both files.
        assert embeds == [len(cwe_kb.KB), 2], f"expected batched queries, got {embeds}"


class TestA4Trace:
    def test_trace_records_the_retriever_that_actually_ran(self, tmp_path):
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)
        assert record.trace["retriever"] == "lexical"
        assert record.trace["files_scanned"] == 2
        assert record.trace["truncated_files"] == 0

    def test_leak_diagnostic_counts_top1_matches(self, tmp_path):
        """The counter agrees with what the retriever independently ranks first.

        Checked against a recomputed expectation rather than a hardcoded number: the
        base is regenerated from MITRE's catalog, so any fixed ranking would go stale
        on the next release and fail for a reason unrelated to this counter.
        """
        r = cwe_kb.LexicalRetriever()
        expected = sum(
            r.top_k(code, 1)[0].benchmark_category == cwe_kb.leaked_category(code)
            for code in (_SQLI, _SAFE)
        )

        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)
        assert record.trace["leak_annotated_files"] == 2
        assert record.trace["top1_leak_matches"] == expected
        assert record.trace["top1_leak_match_frac"] == round(expected / 2, 3)

    def test_leak_diagnostic_ignores_unannotated_files(self, tmp_path):
        """A corpus without the annotation must not divide by zero or report a fraction."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "Plain.java").write_text("class Plain { int x = 1; }\n")
        target = Target("plain", TargetKind.BENCHMARK, source_path=str(src))

        record, _ = run_one(target, "A4", model=RecordingBackend(), config=_LEXICAL)
        assert record.trace["leak_annotated_files"] == 0
        assert record.trace["top1_leak_match_frac"] == 0.0


class TestA4Findings:
    def test_finding_is_pinned_to_the_scanned_path(self, tmp_path):
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        _, findings = run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)

        assert findings, "expected at least one finding"
        for f in findings:
            assert "BenchmarkTest" in (f.location.file or "")

    def test_findings_record_what_was_retrieved(self, tmp_path):
        """findings.json has to show the context a verdict was reached under."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        _, findings = run_one(
            _benchmark(tmp_path), "A4", model=backend, config={**_LEXICAL, "k": 3}
        )
        expected = [e.cwe for e in cwe_kb.LexicalRetriever().top_k(_SQLI, 3)]
        assert findings[0].extra["retrieved_cwes"] == expected

    def test_tp_is_detected(self, tmp_path):
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A4", model=backend, config=_LEXICAL)
        assert record.error is None
        assert record.metrics["tp"] == 1

    def test_retrieval_cost_reaches_the_scorecard(self, tmp_path, monkeypatch):
        """A4's usage must include retrieval, or it reads as cheap as B3."""
        _stub_embedding(monkeypatch)
        record, _ = run_one(
            _benchmark(tmp_path), "A4", model=RecordingBackend(),
            config={"retriever": "embedding"},
        )
        assert record.trace["retriever"] == "embedding"
        # One request for the base, one batch covering both files.
        assert record.input_tokens == 20
