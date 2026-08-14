"""The CWE knowledge base and the retrievers that search it, shared by A4.

Split out of the condition the way :mod:`ast_support` is split out of A2/A3: the
knowledge base is *data* and retrieval is a *ranking* problem, and neither should be
tangled with the per-file scan loop that consumes them.

**Provenance.** Every line of prose in the base comes from MITRE's published CWE
catalog, extracted by ``tools/build_cwe_kb.py`` into ``vulnbench/data/cwe_kb.json``
(which records the catalog version and retrieval date). Nothing in it was written
after looking at the corpus, which is what lets A4 claim retrieval over the CWE
database rather than over descriptions tuned to the benchmark. Re-run the script and
diff the JSON to check that.

**Scope.** Exactly the eleven CWEs OWASP BenchmarkJava v1.2 contains — the same closed
set :data:`llm_common.SCORED_CWES` names, verified against ``expectedresults-1.2.csv``.
Retrieving over eleven entries is a narrow task: with no distractors, picking the right
one is close to free, so A4's contribution is largely the *content* it injects rather
than the difficulty of finding it. Say so in the report; this is retrieval-augmented
generation over a small curated slice of the catalog, not over all ~940 weaknesses.

**A gap worth reporting.** The catalog carries no ``Good`` (fixed-code) Java example for
any of these eleven — six have none in any language — so the base cannot show the model
what a *safe* file looks like, only what a vulnerable one does. MITRE's mitigation prose
is the nearest sourced substitute and is included for that reason, but it describes the
fix in words rather than in code. Since every LLM condition scored so far flags nearly
all the safe cases (FPR 0.85-1.0, tn 0-6), that gap is the most likely reason A4 would
fail to move the false-positive rate.
"""

from __future__ import annotations

import contextlib
import json
import math
import re
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from importlib.resources import files
from typing import Protocol

from ..models import Usage
from ..models.ollama_backend import DEFAULT_HOST

#: Default dense retriever. Chosen by measurement, not reputation — see
#: :class:`EmbeddingRetriever` for the comparison. 621 MB, negligible beside the 9 GB
#: judge model, so both stay resident inside the 16 GB scored-run budget.
DEFAULT_EMBED_MODEL = "embeddinggemma"

#: Queries per embedding request during the prefetch pass. Large enough that a
#: 2740-file sweep is not 2740 round trips, small enough that one request stays well
#: inside the model's context and a failure loses little work.
EMBED_BATCH = 16

#: Which BenchmarkJava category each CWE appears as. Corpus metadata, *not* MITRE
#: data — it comes from ``expectedresults-1.2.csv`` and exists only for the leak
#: diagnostic below, so it is kept out of the sourced JSON.
BENCHMARK_CATEGORIES = {
    22: "pathtraver", 78: "cmdi", 79: "xss", 89: "sqli", 90: "ldapi",
    327: "crypto", 328: "hash", 330: "weakrand", 501: "trustbound",
    614: "securecookie", 643: "xpathi",
}


class RetrievalError(RuntimeError):
    """Retrieval could not be performed (embedding server down, bad reply)."""


@dataclass(frozen=True)
class CWEEntry:
    """One weakness, as published by MITRE.

    ``benchmark_category`` is the token BenchmarkJava puts in each test case's
    ``@WebServlet`` path (``/sqli-00/...``). It is recorded purely as a diagnostic:
    it lets a run measure how often retrieval's top hit merely echoes the category
    the corpus leaks into the source. It is never indexed and never shown to the model.
    """

    cwe: int
    name: str
    description: str
    mitigations: tuple[str, ...]
    #: A vulnerable code sample, Java where the catalog has one. ``None`` if it has none.
    example_language: str | None
    example_code: str | None
    benchmark_category: str

    def as_document(self) -> str:
        """The text a retriever indexes."""
        parts = [self.name, self.description, *self.mitigations]
        if self.example_code:
            parts.append(self.example_code)
        return " ".join(parts)

    def as_context(self) -> str:
        """The block shown to the model."""
        out = [f"CWE-{self.cwe} — {self.name}", f"  {self.description}"]
        if self.mitigations:
            out.append("  Mitigations (a file doing these is likely not vulnerable):")
            out += [f"    - {m}" for m in self.mitigations]
        if self.example_code:
            lang = self.example_language or "unspecified"
            body = "\n".join(f"    {ln}" for ln in self.example_code.splitlines())
            out.append(f"  Example of the weakness ({lang}):\n{body}")
        return "\n".join(out)


def _load(path: str = "data/cwe_kb.json") -> tuple[tuple[CWEEntry, ...], dict]:
    """Read the generated base. A malformed or missing file is a hard error.

    Degrading to a built-in base would let a run silently score against different
    reference material than the one the scorecard names.
    """
    raw = json.loads(files("vulnbench").joinpath(path).read_text(encoding="utf-8"))
    entries = tuple(
        CWEEntry(
            cwe=e["cwe"],
            name=e["name"],
            description=e["description"],
            mitigations=tuple(e["mitigations"]),
            example_language=(e["example"] or {}).get("language"),
            example_code=(e["example"] or {}).get("code"),
            benchmark_category=BENCHMARK_CATEGORIES[e["cwe"]],
        )
        for e in raw["entries"]
    )
    return entries, raw["_source"]


KB, SOURCE = _load()

#: Category token -> entry, for the leak diagnostic (see :class:`CWEEntry`).
BY_CATEGORY: dict[str, CWEEntry] = {e.benchmark_category: e for e in KB}

#: The ``@WebServlet(value = "/sqli-00/BenchmarkTest00052")`` annotation every
#: BenchmarkJava file carries. Its first path segment *is* the ground-truth
#: category, which is why a run measures how often retrieval simply echoes it.
_WEBSERVLET_RE = re.compile(r'@WebServlet\s*\(\s*(?:value\s*=\s*)?"/([A-Za-z0-9_]+)')


def leaked_category(code: str) -> str | None:
    """The category BenchmarkJava's ``@WebServlet`` path leaks, if this file has one."""
    m = _WEBSERVLET_RE.search(code)
    if m is None:
        return None
    # Paths look like "/sqli-00/..."; the trailing index is not part of the token.
    return m.group(1).split("-")[0]


def render_context(entries: list[CWEEntry]) -> str:
    """The retrieved-reference block prepended to the model's user turn."""
    blocks = "\n\n".join(e.as_context() for e in entries)
    return (
        f"Reference material retrieved from the MITRE CWE catalog "
        f"(version {SOURCE['version']}). These are the weaknesses most similar to this "
        f"file; use them to decide, not as a claim that any of them is present.\n\n"
        + blocks
    )


# ---------------------------------------------------------------------------
# Retrievers
# ---------------------------------------------------------------------------

class Retriever(Protocol):
    """Ranks knowledge-base entries against a chunk of source."""

    #: Recorded in the run trace, so a scorecard says which one produced its context.
    name: str
    #: Cost this retriever has incurred so far; folded into the condition's usage.
    usage: Usage

    def top_k(self, query: str, k: int) -> list[CWEEntry]: ...

    def rank_all(self, queries: list[str], k: int) -> list[list[CWEEntry]]:
        """Rank every query up front, so retrieval finishes before judging starts."""
        ...

    def release(self) -> None:
        """Free whatever the retriever holds; called once retrieval is done."""
        ...


_TOKEN_RE = re.compile(r"[A-Za-z][a-z]{2,}")


def _tokenize(text: str) -> list[str]:
    """Words, with Java identifiers split at their camel humps.

    ``getParameter`` yields ``get``/``parameter`` rather than one opaque token, which
    is what lets a knowledge-base entry written in prose match against source code.
    """
    return [t.lower() for t in _TOKEN_RE.findall(text)]


class LexicalRetriever:
    """TF-IDF cosine over the knowledge base. Stdlib only, and fully deterministic.

    The fallback whenever the embedding server is unavailable, and a legitimate
    ablation in its own right: it isolates how much a dense embedding buys over plain
    lexical overlap on a base this small.

    On a 120-file seeded BenchmarkJava sample it puts the true CWE at top-1 for 20.0%
    of files, in the top 3 for 78.3%, and in the top 5 for 98.3%.

    A known weakness behind that weak top-1 rate, worth stating in the report: every
    Benchmark test case shares the same servlet boilerplate — ``request.getCookies()``,
    ``response.setContentType("text/html")``, ``getWriter()`` — and those terms are
    *rare inside an eleven-document base*, so idf scores them as highly informative when
    they are in fact the least informative tokens in the corpus. CWE-614 and CWE-79
    therefore crowd the top of many rankings. Fixing it properly would need document
    frequencies drawn from the corpus rather than the base; ``k`` sidesteps it instead,
    at the cost of a longer prompt.

    One property makes it valuable as a control regardless: it is completely immune to
    the corpus's annotation leak. Masking ``@WebServlet("/sqli-00/…")`` in the query
    changes its accuracy by 0.0pp, because MITRE's prose says "SQL Injection" and never
    "sqli", so the leaked token has nothing to match against. Whatever it retrieves, it
    retrieved from the code.

    Sublinear tf with L2-normalized documents was chosen against binary and raw-tf query
    weighting, and against BM25 and idf-coverage scoring, on the same sample.
    """

    name = "lexical"

    def __init__(self, entries: tuple[CWEEntry, ...] = KB) -> None:
        self.entries = entries
        self.usage = Usage()
        docs = [Counter(_tokenize(e.as_document())) for e in entries]
        n = len(docs)
        df = Counter(term for doc in docs for term in doc)
        self._idf = {t: math.log((n + 1) / (c + 1)) + 1.0 for t, c in df.items()}
        self._vectors = [self._weight(doc) for doc in docs]

    def _weight(self, counts: Counter) -> dict[str, float]:
        """Sublinear tf times idf, L2-normalized so scores are cosines."""
        vec = {
            t: (1.0 + math.log(c)) * self._idf.get(t, 0.0)
            for t, c in counts.items()
            if t in self._idf
        }
        norm = math.sqrt(sum(w * w for w in vec.values()))
        return {t: w / norm for t, w in vec.items()} if norm else {}

    def top_k(self, query: str, k: int) -> list[CWEEntry]:
        q = self._weight(Counter(_tokenize(query)))
        scored = [
            (sum(w * doc.get(t, 0.0) for t, w in q.items()), i)
            for i, doc in enumerate(self._vectors)
        ]
        # -score then index: ties break toward the lower CWE id, so an all-zero
        # query (no overlap at all) still returns the same entries every run.
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        return [self.entries[i] for _, i in scored[:k]]

    def rank_all(self, queries: list[str], k: int) -> list[list[CWEEntry]]:
        return [self.top_k(q, k) for q in queries]

    def release(self) -> None:
        """Nothing to free: the whole retriever is a dict of floats."""


class EmbeddingRetriever:
    """Dense retrieval against an Ollama embedding model.

    The knowledge base is embedded once at construction — eleven short documents, one
    batched request — and only the per-file query costs anything thereafter. Talks to
    the daemon over ``urllib`` for the same reason
    :mod:`vulnbench.models.ollama_backend` does: no third-party dependency to reach a
    server already running locally.

    The default model was picked by measurement on the 120-file sample. "Δleak" is how
    much accuracy is lost when the corpus's ``@WebServlet`` annotation is masked in the
    query — that is, how much of the score was reading the leaked category rather than
    the code:

    ==========================  =====  =====  =====  =======  ======
    retriever                   top-1  top-3  top-5    Δleak    time
    ==========================  =====  =====  =====  =======  ======
    embeddinggemma (default)    95.0%  98.3%  100 %    3.3pp   28.5s
    qwen3-embedding:0.6b        64.2%  98.3%  100 %   46.7pp   65.1s
    bge-m3                      29.2%  50.0%  73.3%        -   84.2s
    nomic-embed-text            19.2%  40.0%  54.2%        -   20.1s
    mxbai-embed-large           12.5%  30.0%  50.8%        -   30.4s
    lexical (no model)          20.0%  78.3%  98.3%    0.0pp    0.0s
    ==========================  =====  =====  =====  =======  ======

    Two results worth carrying into the report. ``embeddinggemma`` is not merely ahead,
    it is reading the *code*: masking the leak costs it 3.3pp. ``qwen3-embedding`` looks
    respectable at top-1 until masked, then collapses from 64.2% to 17.5% — most of its
    apparent skill was recognising ``/sqli-00/``. Ranking retrievers without that
    ablation would have picked a model that had largely learned the benchmark's tell.

    ``nomic-embed-text`` was the original default because the project notes said it had
    been kept on disk; it loses to zero-dependency lexical scoring on every column.
    Applying its documented ``search_query:``/``search_document:`` task prefixes made it
    worse still (top-1 7.5%), so they are not used.

    **Limitation.** Ollama loads ``embeddinggemma`` with a 2048-token context and
    truncates silently: a 19.5k-token input returns a normal-looking vector with
    ``prompt_eval_count=2048`` and no warning (``truncate: false`` turns that into an
    HTTP 400 instead, which would fail the run). BenchmarkJava files are 3-6 KB, well
    inside the window, so scored runs here are unaffected — but ``max_file_bytes``
    defaults to 60,000, so on a corpus with larger files retrieval would silently rank
    against only each file's opening fragment. Cap the query or count the overruns
    before pointing A4 at anything bigger.
    """

    name = "embedding"

    def __init__(
        self,
        model: str = DEFAULT_EMBED_MODEL,
        host: str = DEFAULT_HOST,
        entries: tuple[CWEEntry, ...] = KB,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.entries = entries
        self.timeout = timeout
        self.usage = Usage()
        # Constructing the retriever *is* the availability probe: if the daemon or
        # the model is missing, this raises here, before any file is scanned, so the
        # caller picks a retriever once for the whole run instead of degrading file
        # by file into a row no single method accounts for.
        self._vectors = [_normalize(v) for v in self._embed([e.as_document() for e in entries])]

    def top_k(self, query: str, k: int) -> list[CWEEntry]:
        return self._rank(_normalize(self._embed([query])[0]), k)

    def rank_all(self, queries: list[str], k: int) -> list[list[CWEEntry]]:
        """Embed every query first, in batches, so the judge never shares RAM with us.

        Interleaving one embed call per judge call keeps both models resident. On a
        16 GB machine the 9 GB judge plus an embedding model does not fit in GPU
        memory, so part of the judge spills to CPU and every token it generates gets
        slower — a latency penalty that belongs to the deployment, not to the idea
        being tested. Draining retrieval first lets :meth:`release` hand the memory
        back before the first judge call.
        """
        ranked: list[list[CWEEntry]] = []
        for start in range(0, len(queries), EMBED_BATCH):
            chunk = queries[start : start + EMBED_BATCH]
            ranked += [self._rank(_normalize(v), k) for v in self._embed(chunk)]
        return ranked

    def release(self) -> None:
        """Ask the daemon to evict the embedding model now, not on its idle timer."""
        # Best effort: failing to free memory must not fail an otherwise good run.
        with contextlib.suppress(RetrievalError):
            self._post({"model": self.model, "input": [""], "keep_alive": 0})

    def _rank(self, query_vec: list[float], k: int) -> list[CWEEntry]:
        scored = [
            (sum(a * b for a, b in zip(query_vec, doc, strict=False)), i)
            for i, doc in enumerate(self._vectors)
        ]
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        return [self.entries[i] for _, i in scored[:k]]

    def _post(self, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self.host}/api/embed",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RetrievalError(
                f"embedding request to {self.host} failed: {exc}. Is the daemon "
                f"running (`ollama serve`) and the model pulled (`ollama pull {self.model}`)?"
            ) from exc

    def _embed(self, inputs: list[str]) -> list[list[float]]:
        body = self._post({"model": self.model, "input": inputs})
        vectors = body.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(inputs):
            raise RetrievalError(
                f"embedding server returned {type(vectors).__name__} for {len(inputs)} "
                "input(s); expected a matching list of vectors."
            )
        # Retrieval is real cost, so it lands in the condition's usage rather than
        # quietly making A4 look as cheap as B3.
        self.usage = self.usage + Usage(
            input_tokens=int(body.get("prompt_eval_count", 0)),
            seconds=float(body.get("total_duration", 0)) / 1e9,
        )
        return vectors


def _normalize(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vec))
    return [x / norm for x in vec] if norm else list(vec)


def build_retriever(mode: str, embed_model: str, host: str = DEFAULT_HOST) -> Retriever:
    """The single retriever a run uses, chosen once before the first file.

    ``auto`` prefers embeddings and falls back to lexical when the daemon or the model
    is unreachable. Resolving it here rather than per file is deliberate: a run that
    silently switched retrievers halfway through would produce a scorecard row that no
    single method accounts for.
    """
    if mode == "lexical":
        return LexicalRetriever()
    if mode == "embedding":
        return EmbeddingRetriever(model=embed_model, host=host)
    if mode != "auto":
        raise ValueError(f"unknown retriever {mode!r}; expected auto, embedding, or lexical")
    try:
        return EmbeddingRetriever(model=embed_model, host=host)
    except RetrievalError:
        return LexicalRetriever()
