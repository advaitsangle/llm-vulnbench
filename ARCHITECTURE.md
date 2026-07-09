# Architecture — how vulnbench fits together

A developer onboarding guide. Read this once and you'll know where everything lives and
how to add to it. For *using* the tool (flags, models, config), see [README.md](README.md);
for the research rationale, see [`claude/`](claude/) (internal notes).

## The one-paragraph mental model

vulnbench runs a ladder of vulnerability-detection **conditions** (SAST, DAST, an unaided
LLM, and several LLM+scanner hybrids) against the *same* target app, makes every condition
emit results in *one* shape, and scores them all *the same way* against known ground truth —
recording cost (tokens) and latency along the way. The whole design exists to make that
comparison apples-to-apples.

Everything hangs off **three seams**. Learn these and the rest is plumbing:

| Seam | File | What it guarantees |
|---|---|---|
| **`Finding`** | [`schema.py`](vulnbench/schema.py) | Every condition, whatever tool it used, returns a `list[Finding]`. One shape ⇒ a SAST `file:line` and a DAST `url/param` land in the same scorecard. |
| **`ModelBackend`** | [`models/base.py`](vulnbench/models/base.py) | One `complete(messages, tools?)` call. Swapping a local model for a frontier API is a `--model` flag, not a code fork. |
| **`Condition`** | [`conditions/base.py`](vulnbench/conditions/base.py) | Every matrix cell is `run(target, ctx) -> findings + usage`. Uniform ⇒ cost and latency are measured per cell for free. |

## The pipeline at a glance

```
   CLI args ─┐
             ▼
        cli.py  ──builds──▶  Target          (corpus/target.py — what we scan)
             │               ModelBackend     (models/  — the swappable LLM)      ◀ seam
             │               config dict      (per-condition knobs from --config)
             ▼
     harness.run_one
        │  1. get_condition(id)          conditions/__init__.py  REGISTRY
        │  2. condition.validate(...)    fail fast (missing model? missing source?)
        │  3. condition.run(target, ctx) ───────────────┐
        │                                               ▼
        │                                     ┌──────────────────────┐
        │                                     │     Condition.run     │  ◀ seam
        │                                     │   (one matrix cell)   │
        │                                     └──────────┬───────────┘
        │                         calls as needed        │
        │                ┌──────────────────┬────────────┘
        │                ▼                  ▼
        │           scanners/          models/ModelBackend.complete()
        │         Semgrep / ZAP        Ollama / Anthropic / mock
        │                │                  │
        │                └────────┬─────────┘
        │                         ▼
        │                 list[Finding]   (schema.py — the universal result)       ◀ seam
        │  4. score against ground truth
        ▼
     scoring/  ──pick by target.kind──▶  owasp_benchmark (CSV)  |  webapps_benchmark (list)
        │                                            │
        │                                            ▼
        │                                    Metrics (P / R / F1 / FPR / Youden-J)
        ▼
     RunRecord   (metrics + tokens + latency + provenance + trace)
        │
        ├──▶ report.py                    pretty table + live progress (terminal)
        ├──▶ scorecard.json               (-o)
        ├──▶ findings.json                (--findings-out)
        └──▶ runs/checkpoint-<hash>.json  (auto-saved per cell, for resume)
```

### What happens in one run (`run_one`)

1. **`cli.py`** parses args, builds a `Target`, builds a `ModelBackend` from `--model`
   (if any), and parses `--config` JSON into a knobs dict.
2. **`harness.run_one`** looks the condition up in the `REGISTRY`, calls `validate()`
   (so a missing model or source fails *before* expensive work), then `run()`.
3. The **condition** does its thing — shell out to a scanner, call the model, or both —
   and normalizes everything to `list[Finding]`.
4. **`harness._score`** picks a scorer by `target.kind` and produces `Metrics`.
5. The result is packed into a **`RunRecord`** (metrics + tokens + latency + provenance)
   and rendered by `report.py`; raw data goes to JSON files.
6. Each finished cell is written to a **checkpoint** immediately, so an interrupted sweep
   resumes instead of redoing work.

Errors in a single cell are caught and stored in `RunRecord.error` so the rest of the
matrix keeps running; pass `--debug` to re-raise them instead (use this while developing).

### Two-phase conditions (`TriageCondition`)

C1 and C2 inherit [`TriageCondition`](vulnbench/conditions/base.py), which splits a run into
**scan** (run the scanner) and **triage** (model judges the scanner's output). The phases
can run *separately* (`--scan-out` then `--scan-in`) so you never need the heavy scan stack
(Docker + ZAP) and a big local model resident at the same time — the key trick on a
RAM-bound machine. C3 uses the same idea inverted: **author** rules, then **scan** with them.

## Where things live

```
vulnbench/
  cli.py                entry point: parse args, build Target + model, dispatch
  harness.py            run_one / run_matrix: time, score, pack into RunRecord
  schema.py             Finding + Location — the universal result            ◀ seam
  corpus/
    target.py           Target (what we scan) + TargetKind
  conditions/
    base.py             Condition + TriageCondition contracts                ◀ seam
    __init__.py         REGISTRY {id -> class}, get_condition()
    b1_semgrep.py       B1  SAST baseline (Semgrep)
    b2_zap.py           B2  DAST baseline (OWASP ZAP)
    b3_llm.py           B3  LLM-only — also holds shared source-walk helpers
    c1_llm_semgrep.py   C1  LLM triages Semgrep findings
    c2_llm_zap.py       C2  LLM triages ZAP findings
    c3_llm_rules.py     C3  LLM authors Semgrep rules, then Semgrep runs them
    a1_agents.py        A1  multi-agent scout → hunter → verifier
    llm_common.py       shared LLM prompt contract + JSON-reply parsing
  models/
    base.py             ModelBackend + Completion + Usage                    ◀ seam
    registry.py         build_backend("local:…" | "api:anthropic:…" | "mock")
    ollama_backend.py   local models via the Ollama HTTP API
    anthropic_backend.py  frontier models via the Anthropic API (optional dep)
    mock_backend.py     deterministic offline backend (tests / fresh checkout)
  scanners/
    semgrep_runner.py   run Semgrep, normalize JSON -> Finding  (B1/C1/C3)
    zap_runner.py       run OWASP ZAP, normalize alerts -> Finding  (B2/C2)
    benchmark_crawl.py  seed ZAP from the OWASP Benchmark crawler XML
  scoring/
    metrics_unifier.py  Metrics: precision / recall / F1 / FPR / Youden-J
    owasp_benchmark.py  score vs expectedresults CSV     (--kind benchmark)
    webapps_benchmark.py  fuzzy list-match for realistic apps  (--kind realistic)
  checkpoint.py         crash-safe resume between runs (signature-keyed)
  report.py             progress bar + summary table (rich, optional)
  theme.py              shared CLI look: palette, mascot banner, color
  suite.py              `vulnbench targets` — opt-in app manager
  targets.toml          the test-app catalog (edit to add apps)
```

## Common tasks (recipes)

### Add a new condition (a new matrix cell)

1. Create `conditions/x9_thing.py` with a class subclassing `Condition` (or
   `TriageCondition` if it's scanner-then-model). Set `id`, `label`, `needs_model`,
   and implement `run(self, target, ctx) -> ConditionResult`.
2. Return findings as `list[Finding]`. For LLM conditions, reuse
   `llm_common.SYSTEM_PROMPT` / `OUTPUT_CONTRACT` / `parse_findings()` so your output
   is scored like the others.
3. Register it in [`conditions/__init__.py`](vulnbench/conditions/__init__.py) `REGISTRY`.
4. Add a test in `tests/` (use `--model mock` / `MockBackend` so it runs offline).

That's it — `cli.py`, `harness.py`, scoring, and the report all pick it up automatically.

### Add a new model backend (e.g. OpenAI, vLLM)

1. Create `models/your_backend.py` with a class subclassing `ModelBackend`; implement
   `_complete(messages, tools?) -> Completion`. (The base `complete()` stamps latency
   for you — don't override it.) Set `self.name` to a scorecard-friendly id.
2. Wire a spec prefix into [`models/registry.py`](vulnbench/models/registry.py)
   `build_backend()` (e.g. `api:openai:` → your class).
3. Report `Usage(input_tokens, output_tokens)` so cost metrics keep working.

No condition or scoring code changes.

### Add a new scoring shape / corpus

1. Add a value to `TargetKind` in [`corpus/target.py`](vulnbench/corpus/target.py).
2. Add a loader + scorer in `scoring/` returning `Metrics`.
3. Hook it into `harness._score` (currently a small `if/else` on `target.kind`).

> Heads-up: the OWASP-Benchmark test-case id convention currently lives in
> `schema.py` (`benchmark_case_of`). A genuinely different corpus means teaching your
> scorer that id mapping rather than relying on the schema's built-in one.

## Conventions & gotchas a new dev should know

- **Stdlib-only core.** The harness imports and runs with zero third-party packages.
  Backends/scanners shell out or use `urllib`; `rich` is an *optional* extra that the
  reporter degrades gracefully without. Don't add a hard third-party import to the core
  path — put it behind an optional extra and a lazy import (see `anthropic_backend.py`).
- **`--config` is a free-form dict.** Knobs are read with `ctx.config.get("key", default)`.
  **Unknown keys are silently ignored**, so a typo (`max_file` vs `max_files`) won't error —
  it just runs with the default. The full knob list is in the README's Configuration table.
- **Shared helpers live in two spots today.** Source-tree walking/reading
  (`_iter_source_files`, `_read`) lives in `b3_llm.py`, and JSON parsing helpers in
  `llm_common.py`; other conditions import them. (Known rough edge — they're effectively
  shared utilities.)
- **`validate()` fails fast.** Put cheap preconditions (needs a model? needs a source
  tree / base URL?) there so a misconfigured run errors instantly instead of after a
  long scan.
- **Reproducibility is the point.** Sorted file iteration, frozen config in provenance,
  and recorded tool versions all exist so a scored run is repeatable. Preserve that when
  you add capped/sampled behavior.

## Dev loop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev,pretty]'
.venv/bin/pip install semgrep                 # only if you touch B1/C1/C3

.venv/bin/python -m pytest -q                 # 100% offline (mock model)
.venv/bin/ruff check vulnbench tests          # lint: line-length 100, import order
```

Use `--model mock` for an end-to-end run with no server or keys. See
[README.md](README.md) for the full usage, configuration, and the `targets` app manager.
```
