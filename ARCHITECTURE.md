# Architecture: how vulnbench fits together

A developer onboarding guide. Read this once and you'll know where everything lives and
how to add to it. For *using* the tool (flags, models, config), see [README.md](README.md).

## The one-paragraph mental model

vulnbench runs a ladder of vulnerability-detection **conditions** (SAST, DAST, an unaided
LLM, and several LLM+scanner hybrids) against the same target app. Every condition returns
its results in one shape, and every result is scored the same way against known ground
truth, with tokens and latency recorded per run. That uniformity is what makes the
conditions comparable.

Everything hangs off **three seams**. Learn these three and the rest follows:

| Seam | File | What it guarantees |
|---|---|---|
| **`Finding`** | [`schema.py`](vulnbench/schema.py) | Every condition returns a `list[Finding]`, whatever tool produced it. Because the shape is the same, a SAST `file:line` and a DAST `url/param` land in the same scorecard. |
| **`ModelBackend`** | [`models/base.py`](vulnbench/models/base.py) | One `complete(messages, tools?)` call. Swapping a local model for a frontier API takes a `--model` flag. |
| **`Condition`** | [`conditions/base.py`](vulnbench/conditions/base.py) | Every matrix cell is `run(target, ctx) -> findings + usage`. Because the call is uniform, the harness measures cost and latency for every cell. |

A condition also **declares itself**: its tuning options (`knobs`), the inputs it needs
(`needs_model` / `needs_source` / `needs_url`), and the external tools it shells out to
(`tools`). Those declarations are how the interactive session in
[`wizard.py`](vulnbench/wizard.py) renders menus, preflights dependencies, and prompts for
a missing source tree without knowing any condition by name. Add a condition and the UI
updates itself. Skip a declaration and your knob never appears in the menu.

## The pipeline at a glance

There are **two front-ends** onto the same harness. `vulnbench run …` takes flags;
a bare `vulnbench` starts the interactive session, which builds a *sweep* (many cells
across targets × models × conditions) and renders one comparative matrix. Both call
`harness.run_one` per cell, so everything below is shared.

```mermaid
flowchart TD
    ARGS["CLI args"] --> CLI["cli.py"]
    CLI -- "no subcommand" --> WIZ["<b>wizard.py</b><br/>menus ← REGISTRY · knobs<br/>· targets.toml<br/>preflight ← tools.py<br/>sweep = targets × models<br/>× conditions"]
    CLI -- "run …" --> BUILD
    WIZ -- "one cell at a time" --> BUILD
    BUILD{"build<br/>the inputs"}
    BUILD --> TARGET["<b>Target</b><br/>corpus/target.py<br/>— what we scan"]
    BUILD --> MODEL["<b>ModelBackend</b><br/>models/<br/>— the swappable LLM<br/>◀ seam"]
    BUILD --> CONFIG["<b>config dict</b><br/>per-condition knobs"]

    TARGET --> HARNESS
    MODEL --> HARNESS
    CONFIG --> HARNESS

    subgraph HARNESS["harness.run_one"]
        direction TB
        STEP1["<b>1. get_condition(id)</b><br/>conditions/__init__.py<br/>REGISTRY"] --> STEP2
        STEP2["<b>2. condition.validate(…)</b><br/>fail fast:<br/>missing model?<br/>missing source?"] --> STEP3
        STEP3["<b>3. condition.run(target, ctx)</b>"] --> RUN
        RUN["<b>Condition.run</b><br/>one matrix cell<br/>◀ seam"] --> CALLS
        CALLS{"calls<br/>as needed"} --> SCANNERS
        CALLS --> BACKEND
        SCANNERS["<b>scanners/</b><br/>Semgrep / ZAP"] --> FINDINGS
        BACKEND["<b>models/</b><br/>ModelBackend.complete()<br/>Ollama · Anthropic · mock"] --> FINDINGS
        FINDINGS["<b>list[Finding]</b><br/>schema.py<br/>— the universal result<br/>◀ seam"] --> SCORE
        SCORE["<b>4. score against<br/>ground truth</b>"]
    end

    SCORE --> SCORING["<b>scoring/</b><br/>picks by target.kind"]
    SCORING --> OWASP["owasp_benchmark<br/>(CSV)"]
    SCORING --> WEBAPPS["webapps_benchmark<br/>(list)"]
    OWASP --> METRICS["<b>Metrics</b><br/>P · R · F1<br/>FPR · Youden-J"]
    WEBAPPS --> METRICS
    METRICS --> RECORD["<b>RunRecord</b><br/>metrics + tokens<br/>+ latency<br/>+ provenance + trace<br/><i>counts findings,<br/>doesn't carry them</i>"]

    RECORD --> REPORT["<b>report.py</b><br/>summary() one target<br/>matrix() a sweep<br/>+ live progress"]
    RECORD --> SCORECARD["<b>scorecard.json</b><br/>(-o)"]
    FINDINGS --> FINDINGSOUT["<b>findings.json</b><br/>(--findings-out)<br/>flat array,<br/>every cell merged"]
    RECORD --> CHECKPOINT["<b>runs/checkpoint-&lt;hash&gt;.json</b><br/>record + findings<br/>per clean cell,<br/>for resume"]
    FINDINGS --> CHECKPOINT
```

### What happens in one run (`run_one`)

1. **`cli.py`** parses args, builds a `Target`, builds a `ModelBackend` from `--model`
   (if any), and parses `--config` JSON into a knobs dict.
2. **`harness.run_one`** looks the condition up in the `REGISTRY`, calls `validate()`
   (so a missing model or source fails *before* expensive work), then `run()`.
3. The **condition** does its thing, shelling out to a scanner, calling the model, or
   both, and normalizes everything to `list[Finding]`.
4. **`harness._score`** picks a scorer by `target.kind` and produces `Metrics`.
5. The result is packed into a **`RunRecord`** (metrics + tokens + latency + provenance)
   and rendered by `report.py`; raw data goes to JSON files. `run_one` returns
   `(RunRecord, list[Finding])`. The record stores only a count (`n_findings`), so the
   findings travel alongside it and are written to their own file (`--findings-out`, or
   `<scorecard>.findings.json` in the interactive session).
6. Each **error-free** cell is written to a **checkpoint** as soon as it finishes, record
   and findings together, so an interrupted sweep resumes where it stopped and still
   writes a complete findings.json. A cell that errored stays out of the checkpoint, so it
   runs again on resume.

The harness catches an error in a single cell and stores it in `RunRecord.error` so the
rest of the matrix keeps running; pass `--debug` to re-raise it while you're developing.
The same policy holds one level up. A mistake on the command line (malformed `--config`
JSON, an unrecognized `--model` spec) exits with a one-line usage error before any cell
runs, and a backend the wizard can't build mid-sweep (missing API key or optional package)
fails only its own cells via `RunRecord.failed`.

### Two-phase conditions (`TriageCondition`)

C1 and C2 inherit [`TriageCondition`](vulnbench/conditions/base.py), which splits a run into
**scan** (run the scanner) and **triage** (model judges the scanner's output). The phases
can run *separately* (`--scan-out` then `--scan-in`), so you never need the heavy scan stack
(Docker + ZAP) and a big local model resident at the same time. That is the trick that
makes the whole thing work on a RAM-bound machine. C3 applies the same split in reverse:
**author** rules, then **scan** with them.

## Where things live

```
vulnbench/
  cli.py                entry point: parse args, build Target + model, dispatch
  wizard.py             bare `vulnbench`: interactive sweep (menus, preflight, matrix)
  harness.py            run_one / run_matrix: time, score, pack into RunRecord
  schema.py             Finding + Location + their JSON format               ◀ seam
  corpus/
    target.py           Target (what we scan) + TargetKind
  conditions/
    base.py             Condition + TriageCondition contracts + Knob         ◀ seam
    __init__.py         REGISTRY {id -> class}, get_condition()
    b1_semgrep.py       B1  SAST baseline (Semgrep)
    b2_zap.py           B2  DAST baseline (OWASP ZAP)
    b3_llm.py           B3  LLM-only (flat per-file pass)
    source_files.py     shared source-tree walking/reading + its knobs
    c1_llm_semgrep.py   C1  LLM triages Semgrep findings
    c2_llm_zap.py       C2  LLM triages ZAP findings
    c3_llm_rules.py     C3  LLM authors Semgrep rules, then Semgrep runs them
    a1_agents.py        A1  multi-agent scout → hunter → verifier
    a5_parse.py         A5  model cuts the file to its risky portion, then B3 evaluates it
    a7_a8_fewshot_cot.py  A7 few-shot labeled examples · A8 chain-of-thought
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
  report.py             progress bar + summary/matrix tables (rich, optional)
  theme.py              shared CLI look: palette, mascot banner, color
  tui.py                reusable multi-select menu + prompts (raw TTY, text fallback)
  tools.py              external deps (semgrep / ZAP / Ollama): detect, install, hint
  suite.py              `vulnbench targets` — opt-in app manager
  targets.toml          the test-app catalog (edit to add apps)
```

## Common tasks (recipes)

### Add a new condition (a new matrix cell)

1. Create `conditions/x9_thing.py` with a class subclassing `Condition` (or
   `TriageCondition` if it's scanner-then-model) and implement
   `run(self, target, ctx) -> ConditionResult`.
2. **Declare what it is and what it needs.** The CLI and the interactive session read
   these attributes, so nothing else needs editing:

   ```python
   class X9Thing(Condition):
       id = "X9"
       label = "Thing (one line, shown in every menu)"
       needs_model = True          # a --model is required
       needs_source = True         # a source tree is required (or needs_url for DAST)
       tools = ("semgrep",)        # external deps, preflighted before a run
       knobs = (
           Knob("max_hops", "int", 3, help="how far to follow a taint chain"),
       )
   ```

   Read knobs with `self.cfg(ctx, "max_hops")`, **never** `ctx.config.get("max_hops", 3)`.
   See the gotcha under "Conventions" below for why the second form breaks silently.
3. Return findings as `list[Finding]`. For LLM conditions, reuse
   `llm_common.SYSTEM_PROMPT` / `OUTPUT_CONTRACT` / `parse_findings()` so your output
   is scored like the others.
4. Register it in [`conditions/__init__.py`](vulnbench/conditions/__init__.py) `REGISTRY`.
5. Add a test in `tests/` (use `--model mock` / `MockBackend` so it runs offline).

`cli.py`, `harness.py`, scoring, the report, and every wizard menu (including the knob
prompts and the dependency preflight) then pick the condition up automatically.

> Needs a tool nobody uses yet? Add a `Tool` to [`tools.py`](vulnbench/tools.py) with a
> `check`, an optional `install_cmd`, and a `hint`, then name its key in `tools`. Give a
> daemon a `startup_wait` so the probe polls while it boots; a package doesn't need one.
> If the command depends on the machine's current state (Docker running, a compose file
> present), supply `install_cmd_factory` instead. It is re-evaluated at the moment the
> user is actually asked.

#### When is a condition done?

Every cell in the matrix has to be comparable with every other one, so a condition that
runs and scores wrongly does real damage to the results. A condition is ready for review
when all six of these hold:

1. **It's registered and self-declaring.** One `REGISTRY` line, with `knobs`,
   `needs_model`, `needs_source`, `needs_url`, and `tools` filled in, so it appears in
   `vulnbench run --condition`, in the wizard menus, and in the dependency preflight
   without anyone editing the CLI.
2. **It returns `list[Finding]`** with the location fields populated for its target kind:
   `file` plus `line` for source targets, `url` plus `param` for web targets. The scorer
   counts a finding it can't match as a miss, which is where recall quietly disappears.
3. **It has an offline test.** `MockBackend` / `--model mock`, no network, no Docker, no
   API key. CI runs on a bare GitHub runner and has to stay green there.
4. **You've run it once on a real target**, beyond the mock, and it produced a scorecard
   row with plausible metrics. Attach that row to your PR. A mock test shows the condition
   is wired up correctly. A real run is the evidence that it detects anything.
5. **`pytest -q` and `ruff check vulnbench tests` are clean**, since those are the required
   CI checks.
6. **New knobs are in the README's Configuration table**, so a user can find them without
   reading your source.

### Add a new model backend (e.g. OpenAI, vLLM)

1. Create `models/your_backend.py` with a class subclassing `ModelBackend`; implement
   `_complete(messages, tools?) -> Completion`. (The base `complete()` stamps latency
   for you, so don't override it.) Set `self.name` to a scorecard-friendly id.
2. Wire a spec prefix into [`models/registry.py`](vulnbench/models/registry.py)
   `build_backend()` (e.g. `api:openai:` → your class), and teach `is_valid_spec()`
   the same grammar. That's what lets the wizard reject a typo at entry time.
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
  Backends and scanners shell out or use `urllib`; `rich` is an optional extra, and the
  reporter falls back to plain text without it. Keep third-party imports off the core
  path: put them behind an optional extra and a lazy import (see `anthropic_backend.py`).
- **Read knobs with `self.cfg(ctx, name)`, never `ctx.config.get(name, default)`.** A
  `Knob`'s `default` is the single source of truth. `cfg()` falls back to it, so the value
  the wizard shows and the value your code runs with stay in step. Write a second default
  into a `.get()` call and the two drift apart: the menu offers `3`, the run uses `5`, and
  the scorecard is wrong with nothing to flag it.
  `test_every_cfg_read_names_a_declared_knob` catches reads of an undeclared knob, and a
  duplicated default is invisible to it.
- **Declare every knob.** Every option a condition accepts is a `Knob` in its `knobs`
  tuple. `Condition.all_knobs()` merges the MRO, so `TriageCondition` hands
  `scan_out`/`scan_in` to C1 and C2 without either restating them. Mark handoff knobs (the
  files that pass data between phases) `advanced=True` to keep them out of the wizard's
  tuning menu.
- **The CLI checks `--config` keys against declared knobs.** It rejects a key that none of
  the chosen conditions declare, so a typo like `max_file` for `max_files` fails before the
  run starts. The wizard only offers declared knobs to begin with. Full list: the README's
  Configuration table.
- **Shared helpers live in one place.** Source-tree walking and reading
  (`iter_source_files`, `read_capped`, `SCAN_KNOBS`) live in `conditions/source_files.py`,
  and JSON parsing lives in `llm_common.py`. The ZAP driver (`_run_zap_from_config`,
  `ZAP_KNOBS`) stays in `b2_zap.py` where it was first used, and C2 imports it from there,
  because that pair is the only thing sharing it.
- **`validate()` mostly writes itself.** Set `needs_model`, `needs_source`, or `needs_url`
  and the base class raises a clear error before any expensive work, so no condition needs
  its own `validate()`. Override it only when a knob *relaxes* a requirement, and put the
  rule as high up as it applies: `scan_in` removes the need for scanner input, so
  `TriageCondition` handles it once for both C1 and C2. C3 overrides directly because its
  `rules_in` removes the need for a model.
- **Declare external tools so preflight can check them.** Anything a condition shells out
  to belongs in `tools`. Preflight then catches a missing scanner in the first second of a
  run, when it costs a prompt to fix, instead of thirty minutes into a sweep.
- **Keep runs reproducible.** Sorted file iteration, frozen config in provenance, and
  recorded tool versions all exist so a scored run can be repeated exactly. Preserve that
  when you add capped or sampled behavior.

## Dev loop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev,pretty]'
.venv/bin/pip install semgrep                 # only if you touch B1/C1/C3

.venv/bin/python -m pytest -q                 # 100% offline (mock model)
.venv/bin/ruff check vulnbench tests          # lint: line-length 100, import order
```

Use `--model mock` for an end-to-end run with no server or keys. CI runs both checks above
on every PR, so run them before you push.

## Working on this repo (contribution workflow)

`main` is **branch-protected**, so nobody pushes to it directly. Every change lands through
a pull request that passes CI and review. The whole flow, end to end:

**1. One branch, one PR, one condition.** Branch off an up-to-date `main` and name the
branch for the work (`a4-rag`, `a8-cot`, …):

```bash
git checkout main && git pull
git checkout -b a4-rag
```

Keep a PR to a single condition: its new `conditions/xN_thing.py`, its test, and the one
`REGISTRY` line (see "Add a new condition" above). Small, single-purpose PRs review fast
and don't collide. The only file two contributors touch in common is
`conditions/__init__.py` (the registry), and a one-line conflict there is trivial to
resolve.

**2. Before you push, run what CI runs.** A PR can't merge until CI is green:
`ruff check vulnbench tests` and `pytest -q`, across Python 3.11 / 3.12 / 3.13
(`.github/workflows/ci.yml`). Run both locally first so the PR goes green on the first try.

**3. Open the PR against `main`.** To merge it needs:

- **CI green**, meaning the three `lint-and-test` jobs.
- **One approving review**, from somebody other than the author, since you can't approve
  your own PR. Pushing new commits dismisses an approval you already have, so get the PR
  final before you ask for review.
- **Code-owner review where it applies.** If your PR touches a frozen core path, the code
  owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)) has to approve. Adding a condition
  normally touches only your new file plus the one registry line, and that registry line
  lives in a co-owned file, so expect a maintainer review on it.

Merges are **squashed**, so your branch history doesn't need to be tidy; one clean commit
lands on `main` per PR. Write a clear PR title and description.

**4. Leave the frozen core alone.** The harness, scoring, model backends, `schema.py`, and
the `Condition` contract (`base.py` plus the registry) are stable API that your condition
builds *on top of*, and they should stay fixed while you add a condition. If you think a
core change is genuinely needed, raise it in an issue or a message to the maintainer
*before* you open a PR.

**5. New dependencies go behind an optional extra and a lazy import.** The core is
stdlib-only (see the conventions above). If your condition needs a library (embeddings, a
parser, and so on), declare it as an optional extra in `pyproject.toml`
(`[project.optional-dependencies] a4 = ["…"]`) and import it *inside* `run()`, raising a
message that names the install command when it's missing. A third-party import on the core
path breaks `import vulnbench` for everyone else.

See [README.md](README.md) for the full usage, configuration, and the `targets` app manager.
