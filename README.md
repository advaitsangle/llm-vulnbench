# vulnbench

A benchmark harness for **LLM-augmented web vulnerability detection**. It runs a
ladder of detection *conditions* — SAST, DAST, an unaided LLM, and several
LLM+scanner combinations — against the same vulnerable applications, normalizes
every result to one finding schema, and scores them the same way against known
ground truth. The goal is an apples-to-apples answer to "does the LLM actually
help, and which way of wiring it in works?"

vulnbench is built to be **reconfigured, not rewritten**: the core is a small,
stdlib-only harness, and the model, the scanners, and the target apps are all
things you plug in. Swap the model with a flag; install only the tools the
conditions you care about need; point it at whatever benchmark you have.

## Lightweight core, pick-your-own everything else

The package itself has **zero required dependencies** — it imports and runs on a
clean Python 3.11+. Everything heavy is opt-in, so you only install what your
chosen conditions actually use:

| You want… | Install | Used by |
|-----------|---------|---------|
| pretty CLI (banner, progress bar, color table) | `pip install 'vulnbench[pretty]'` (`rich`) | all runs (degrades to plain text without it) |
| a local model | [Ollama](https://ollama.com) + `ollama pull <model>` | B3, C1, C2, C3, A1 |
| a frontier model | `pip install 'vulnbench[anthropic]'` + `ANTHROPIC_API_KEY` | B3, C1, C2, C3, A1 |
| static analysis | `pipx install semgrep` | B1, C1, C3 |
| dynamic analysis | Docker (`deploy/` brings up the app + a ZAP daemon) | B2, C2 |

Nothing above is needed to try the harness: the built-in `mock` model and the
included tests run fully offline.

## Configure the model — it's a flag, not a fork

Every LLM condition talks to one `ModelBackend.complete()` seam, so the model is
a single `--model` argument:

```
--model mock                              # offline, deterministic (no server)
--model local:qwen3-coder:14b            # any Ollama model, local
--model api:anthropic:claude-opus-4-8    # any Anthropic model (frontier ceiling)
```

Adding a provider is a small backend class behind the same interface (see
[`vulnbench/models/`](vulnbench/models/)); the conditions and scoring don't change.

## The condition ladder

| id | condition | needs | status |
|----|-----------|-------|--------|
| B1 | Semgrep only (SAST baseline) | scanner | ✅ |
| B2 | OWASP ZAP only (DAST baseline) | scanner (Docker) | ✅ |
| B3 | LLM only (unaided model reads source) | model | ✅ |
| C1 | LLM + Semgrep output (scanner-assisted triage) | model + scanner | ✅ |
| C2 | LLM + ZAP output (scanner-assisted triage, DAST) | model + scanner | ✅ |
| C3 | LLM-authored Semgrep rules (LLM improves the tool) | model + scanner | ✅ |
| A1 | Multi-agent roles (scout / hunt / verify) | model | ✅ |

`vulnbench list` prints the live matrix. Conditions are independent classes
(`run(target) -> findings + usage`), so you can mix and match which cells you run
and add your own without touching the rest.

## Architecture

Three seams keep the matrix uniform and the comparisons fair:

- **`schema.Finding`** — one normalized record (`vuln_class` CWE id, `location`,
  `confidence`, `verdict`, evidence) so a SAST `file:line` and a DAST `url/param`
  land in the same scorecard.
- **`models.ModelBackend`** — one `complete(prompt, tools?)` interface; `local:`
  (Ollama), `api:anthropic:` (frontier ceiling), and `mock` (offline) backends sit
  behind it. Swapping the model is a flag, not a fork.
- **`conditions.Condition`** — every cell is `run(target) -> findings + usage`, so
  cost (tokens) and latency (wall-clock) are measured per condition for free.

Scoring is decoupled: `scoring/benchmark.py` auto-scores OWASP Benchmark against
`expectedresults-*.csv`; `scoring/listmatch.py` fuzzy-matches realistic apps
(Juice Shop / WebGoat / DVWA) against a curated vuln list.

```
vulnbench/
  schema.py            common finding schema
  models/              base + ollama + anthropic + registry (mock)
  scanners/            semgrep_runner (B1/C1), zap_runner (B2)
  conditions/          base, b1, b2, b3, c1, c2, c3, a1
  corpus/              Target descriptor
  scoring/             metrics, benchmark CSV matcher, listmatch
  harness.py           run_one / run_matrix pipeline (+ provenance)
  checkpoint.py        crash-safe resume between runs
  report.py            banner + progress bar + summary table (rich, optional)
  cli.py               `vulnbench` entry point
```

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev,pretty]'

# See the matrix
.venv/bin/python -m vulnbench.cli list

# Run a condition and score it (mock model = no server needed)
.venv/bin/python -m vulnbench.cli run \
    --condition B1 C1 --source ./src \
    --ground-truth ./expectedresults-1.2.csv --kind benchmark \
    --model mock -o scorecard.json --findings-out findings.json

# Tests + lint
.venv/bin/python -m pytest -q
.venv/bin/ruff check vulnbench tests
```

### Output: highlight on screen, detail in files

With `rich` installed (the `pretty` extra), `run` shows a banner, a live progress
bar across the conditions, and a color-coded summary table (F1 green ≥ 0.70,
yellow ≥ 0.50, red below). The full data goes to files: `-o scorecard.json`
(metrics + provenance + trace per condition) and `--findings-out findings.json`
(every normalized finding, for FP/FN auditing). Pretty mode auto-engages on a
TTY; piping or `--plain` falls back to plain text, and without `rich` it degrades
gracefully.

```
                     vulnbench · BenchmarkJava
╭──────┬──────────┬──────┬────────┬──────┬──────┬─────────┬────────╮
│ Cond │ Findings │ Prec │ Recall │  F1  │ FPR  │ Latency │ Tokens │
├──────┼──────────┼──────┼────────┼──────┼──────┼─────────┼────────┤
│ B1   │     1909 │ 0.62 │   0.59 │ 0.61 │ 0.39 │   17.9s │      0 │
╰──────┴──────────┴──────┴────────┴──────┴──────┴─────────┴────────╯
```

### Pause and resume (on by default)

A sweep can be slow — a local 14B model triaging hundreds of files takes a while,
and a laptop can sleep or run out of RAM mid-run. So every finished condition is
**checkpointed to disk the moment it completes** (`runs/checkpoint-<hash>.json`,
gitignored). Re-run the same command and it skips the conditions that already
finished and continues from where it stopped:

```bash
# interrupted after B1, B3 finished? just run it again — B1/B3 are reused,
# only C1 actually re-runs:
.venv/bin/python -m vulnbench.cli run --condition B1 B3 C1 --source ./src \
    --ground-truth ./expectedresults-1.2.csv --model local:qwen3-coder:14b
```

The checkpoint is keyed on the run inputs (target, model, config, ground truth),
so changing any of them starts fresh automatically. Use `--fresh` to force a
clean run, or `--checkpoint PATH` to choose where it's stored.

### Getting an OWASP Benchmark target

The reference scored target is the **OWASP BenchmarkJava** app — 2740 Java test
cases, each labeled with one CWE as a true/false positive. It isn't vendored (it's
large and gitignored); clone it into `targets/` once:

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava targets/BenchmarkJava
```

That single clone gives you everything the harness needs:

- **Source tree** `targets/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/`
  — the `--source` for the static conditions (B1, B3, C1).
- **Ground truth** `targets/BenchmarkJava/expectedresults-1.2.csv` — the `--ground-truth`
  every condition is scored against.
- **DAST crawl spec** `targets/BenchmarkJava/data/benchmark-crawler-http.xml` — used to
  seed ZAP for the dynamic conditions (B2, C2).

A scored static run then needs no extra services:

```bash
.venv/bin/python -m vulnbench.cli run \
    --condition B1 \
    --source targets/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
    --ground-truth targets/BenchmarkJava/expectedresults-1.2.csv \
    --kind benchmark -o scorecard.json
```

> Trying it on a slice? Point `--source` at a handful of `BenchmarkTestNNNNN.java`
> files (or pass `--config '{"max_files": 20}'`). Partial runs are scored only over
> the cases they examined, so the recall number stays honest.

Bringing your own corpus? The scorer supports two shapes: an OWASP-style
`expectedresults` CSV (`--kind benchmark`), or a curated vuln-list JSON for
realistic apps (`--kind realistic`, fuzzy-matched by `scoring/listmatch.py`).

For the **dynamic** conditions (B2/C2) the app has to be *running*; the Docker stack
in [`deploy/`](deploy/README.md) builds the BenchmarkJava WAR and a ZAP daemon for you
(`docker compose -f deploy/docker-compose.yml up --build`).

## Scoring model

Each OWASP Benchmark test case contributes one confusion-matrix cell: a case is
*detected* when the tool reports its expected CWE in that test case's file.
Metrics: precision, recall, F1, false-positive rate, and Youden's J (the
Benchmark's own score = recall − FPR), plus tokens and latency.

## Status

Implemented: B1, B2 (ZAP DAST, with the `deploy/` Docker stack), B3, C1, C2
(phased scan/triage), C3 (LLM-authored Semgrep rules, phased author/score), A1
(multi-agent scout / hunt / verify), Benchmark scoring with honest subset scoping,
checkpoint/resume, and the model/condition/scoring seams with tests. Next: the
realistic-app vuln-list curation.
