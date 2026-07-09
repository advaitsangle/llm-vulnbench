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

## Configuration

Everything you'd want to change is a **CLI flag or an environment variable** — no code
edits. The three things you configure most are the model, a few environment variables, and
optional per-condition knobs.

### Pick a model — `--model`

Every LLM condition talks to one `ModelBackend.complete()` seam, so the model is a single
argument. Three kinds are built in:

| `--model` value | What it is | One-time setup |
|---|---|---|
| `mock` | offline, deterministic; canned schema-valid replies | nothing — built in |
| `local:<name>` | **your own local model** via [Ollama](https://ollama.com) | `ollama pull <name>` (daemon running) |
| `api:anthropic:<name>` | **a frontier API model** (the "ceiling") | `pip install 'vulnbench[anthropic]'` + an API key |

```bash
# 1) offline smoke test — no server, no keys, nothing to install
vulnbench run --condition B3 --source ./src --ground-truth gt.csv --model mock

# 2) your own LOCAL model through Ollama — just pull it and name it
ollama pull qwen2.5-coder:14b
vulnbench run --condition B3 --source ./src --ground-truth gt.csv \
    --model local:qwen2.5-coder:14b
# any Ollama model works — swap the name:  local:llama3.1:8b  ·  local:deepseek-coder-v2:16b

# 3) a frontier model via the Anthropic API
pip install 'vulnbench[anthropic]'
export ANTHROPIC_API_KEY=sk-ant-...          # your key
vulnbench run --condition B3 --source ./src --ground-truth gt.csv \
    --model api:anthropic:claude-opus-4-8
```

Want a provider that isn't here (OpenAI, vLLM, a self-hosted endpoint)? It's one small
backend class behind the same `ModelBackend.complete()` interface — see the "add a model
backend" recipe in [ARCHITECTURE.md](ARCHITECTURE.md). The conditions and scoring don't change.

> **Local model on a non-default host?** The `local:` backend talks to Ollama at
> `http://localhost:11434` (Ollama's default). A custom host/port isn't a CLI flag yet —
> construct `OllamaBackend(host=...)` from Python, or run Ollama on the default address.

### Environment variables

| Variable | Used for | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | the `api:anthropic:` backend (your key) | *(required for that backend)* |
| `VULNBENCH_TARGETS_DIR` | where `vulnbench targets` installs / looks for apps | `<repo>/targets` |
| `NO_COLOR` | disable all color and the banner | unset |

### Per-condition knobs — `--config '{...}'`

Conditions accept optional tuning knobs as a JSON object. **Unknown keys are silently
ignored**, so double-check spelling (`max_files`, not `maxfiles`). The common ones:

| Knob | Conditions | Default | Meaning |
|---|---|---|---|
| `max_files` | B3, A1 | all | cap on source files examined (reproducible sorted subset) |
| `max_file_bytes` | B3, C1, A1 | 60000 | per-file read cap (truncation is recorded, not silent) |
| `semgrep_ruleset` | C1 | `p/owasp-top-ten` | the Semgrep config/ruleset to run |
| `semgrep_timeout` | C3 | 1800 | Semgrep timeout (s) for the authored-rules scan |
| `min_risk` | A1 | 0.0 | scout deep-dives only files it scores ≥ this (0 = all) |
| `triage`, `verify` | A1 | true | ablation toggles for the scout / verifier roles |
| `triage_head_bytes`, `triage_batch` | A1 | 1500, 10 | scout's per-file head size and files-per-batch |
| `author_files`, `author_max_bytes` | C3 | 8, 4000 | example files (and bytes each) shown to the rule author |
| `rules_out` / `rules_in` | C3 | — | author rules to a file / score with an existing rules file |
| `scan_out` / `scan_in` | C1, C2 | — | split the scanner phase from model triage (also `--scan-out`/`--scan-in`) |
| `zap_url`, `zap_api_key`, `zap_recurse`, `zap_max_wait` | B2, C2 | `localhost:8090`, `""`, true, 1800 | ZAP daemon connection + scan knobs |
| `zap_seed_crawler`, `zap_seed_limit` | B2, C2 | — | seed ZAP from a Benchmark crawler XML (fair DAST scoring) |
| `zap_disable_scanners` | B2, C2 | `["40026"]` | active-scan plugin ids to skip |

```bash
# 20-file slice with a bigger per-file budget
vulnbench run --condition B3 --source ./src --ground-truth gt.csv \
    --model local:qwen2.5-coder:14b --config '{"max_files": 20, "max_file_bytes": 80000}'
```

New to the codebase? [ARCHITECTURE.md](ARCHITECTURE.md) explains how it all fits together
and how to add a condition, a model backend, or a scorer.

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

> Full developer onboarding — the pipeline diagram, the run lifecycle, and how to add a
> condition / model / scorer — is in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

Three seams keep the matrix uniform and the comparisons fair:

- **`schema.Finding`** — one normalized record (`vuln_class` CWE id, `location`,
  `confidence`, `verdict`, evidence) so a SAST `file:line` and a DAST `url/param`
  land in the same scorecard.
- **`models.ModelBackend`** — one `complete(prompt, tools?)` interface; `local:`
  (Ollama), `api:anthropic:` (frontier ceiling), and `mock` (offline) backends sit
  behind it. Swapping the model is a flag, not a fork.
- **`conditions.Condition`** — every cell is `run(target) -> findings + usage`, so
  cost (tokens) and latency (wall-clock) are measured per condition for free.

Scoring is decoupled: `scoring/owasp_benchmark.py` auto-scores OWASP Benchmark against
`expectedresults-*.csv`; `scoring/webapps_benchmark.py` fuzzy-matches realistic apps
(Juice Shop / WebGoat / DVWA) against a curated vuln list.

```
vulnbench/
  schema.py            common finding schema
  models/              base + ollama + anthropic + registry (mock)
  scanners/            semgrep_runner (B1/C1), zap_runner (B2)
  conditions/          base, b1, b2, b3, c1, c2, c3, a1
  corpus/              Target descriptor
  scoring/             metrics_unifier, owasp_benchmark (CSV), webapps_benchmark (list)
  harness.py           run_one / run_matrix pipeline (+ provenance)
  checkpoint.py        crash-safe resume between runs
  theme.py             shared CLI look: palette, mascot banner, rich/ANSI color
  report.py            progress bar + summary table (rich, optional)
  suite.py             `targets` manager: catalog + registry + point-or-install
  targets.toml         the test-app catalog (the editable list of options)
  cli.py               `vulnbench` entry point (list / run / targets)
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

### Install it as a command

To get a `vulnbench` command on your `PATH` (instead of `python -m vulnbench.cli`),
install it with [pipx](https://pipx.pypa.io) — an isolated app install that works
even on a PEP-668 "externally managed" system Python:

```bash
pipx install -e '.[pretty]'                       # from a local checkout
# or, once the repo is public:
pipx install 'git+https://github.com/advaitsangle/vulnbench.git'

vulnbench list                                    # now works from anywhere
```

Every example below then drops the `.venv/bin/python -m vulnbench.cli` prefix and
just says `vulnbench …`.

### Quality checks (tests, lint, review)

```bash
.venv/bin/python -m pytest -q          # offline test suite
.venv/bin/ruff check vulnbench tests   # lint (line-length 100, import order, …)
```

This repo is developed with Claude Code; the code-quality passes are **slash-commands**
you run inside a Claude Code session (not shell scripts):

| Command | What it does |
|---------|--------------|
| `/simplify` | reuse / simplification / efficiency cleanup of the current diff, then applies fixes |
| `/code-review` | reviews the diff for correctness bugs (`--fix` to apply, `--comment` to post on a PR) |
| `/security-review` | security review of the pending changes |

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
    --ground-truth ./expectedresults-1.2.csv --model local:qwen2.5-coder:14b
```

The checkpoint is keyed on the run inputs (target, model, config, ground truth),
so changing any of them starts fresh automatically. Use `--fresh` to force a
clean run, or `--checkpoint PATH` to choose where it's stored.

### Test apps: the `targets` manager

The vulnerable apps under test are **never shipped with the repo** (they're large
and live in the gitignored `targets/`). `vulnbench targets` is an opt-in manager
for them — an arrow-key menu (↑/↓ move, space toggle, enter confirm, `q`/Ctrl-C
cancel) over a catalog defined in [`vulnbench/targets.toml`](vulnbench/targets.toml):

```bash
vulnbench targets            # interactive: pick apps, then point-or-install each
vulnbench targets --list     # show the catalog + where each app is linked
vulnbench targets --all      # select everything (skip the menu)
vulnbench targets --update   # pull already-linked git clones to latest upstream
```

Each app's location is a **reference, not a fixed path** (stored in the gitignored
`targets/registry.json`). For an app that isn't linked yet you choose, per app:

- **point** at a copy you already have sitting around (any directory — no clone), or
- **install** a fresh shallow clone into a location you pick (default `targets/<name>`).

A clone already at the default `targets/<name>` is auto-recognized, so existing
checkouts keep working. To wire a linked app straight into a run, ask for its path:

```bash
vulnbench run --condition B1 \
    --source "$(vulnbench targets --path juice-shop)" \
    --ground-truth ./vulns.json --kind realistic
```

Add an app by appending an `[[app]]` block to `targets.toml` — no code changes.
The catalog ships with Juice Shop, DVWA, WebGoat, and OWASP BenchmarkJava.

### Getting an OWASP Benchmark target

The reference scored target is the **OWASP BenchmarkJava** app — 2740 Java test
cases, each labeled with one CWE as a true/false positive. `vulnbench targets`
can fetch it (it's in the catalog), or clone it into `targets/` directly:

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
realistic apps (`--kind realistic`, fuzzy-matched by `scoring/webapps_benchmark.py`).

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
