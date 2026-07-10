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

> **Building on vulnbench?** Developer onboarding — the architecture, how to add a
> condition / model / scorer, the dev loop, and the contribution workflow — lives in
> **[ARCHITECTURE.md](https://github.com/advaitsangle/llm-vulnbench/blob/main/ARCHITECTURE.md)**.

## What it does

### The condition ladder (WIP)

- B1 — Semgrep only (SAST baseline)
- B2 — OWASP ZAP only (DAST baseline)
- B3 — LLM only (unaided model reads source)
- C1 — LLM + Semgrep output (scanner-assisted triage)
- C2 — LLM + ZAP output (scanner-assisted triage, DAST)
- C3 — LLM-authored Semgrep rules (LLM improves the tool)
- A1 — Multi-agent roles (scout / hunt / verify)

`vulnbench list` prints the live matrix. Conditions are independent classes
(`run(target) -> findings + usage`), so you can mix and match which cells you run.

### How it scores

Each OWASP Benchmark test case contributes one confusion-matrix cell: a case is
*detected* when the tool reports its expected CWE in that test case's file.
Metrics: precision, recall, F1, false-positive rate, and Youden's J (the
Benchmark's own score = recall − FPR), plus tokens and latency.

Bringing your own corpus? The scorer supports two shapes: an OWASP-style
`expectedresults` CSV (`--kind benchmark`), or a curated vuln-list JSON for
realistic apps (`--kind realistic`, fuzzy-matched by `scoring/webapps_benchmark.py`).

## Installation

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
included tests run fully offline. And you don't have to set these up in advance — the
interactive session checks for whatever your chosen conditions need and offers to install
Semgrep or start the ZAP daemon for you.

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[pretty]'
.venv/bin/python -m vulnbench.cli list          # see the matrix
```

### Install it as a command

To get a `vulnbench` command on your `PATH` (instead of `python -m vulnbench.cli`),
install it with [pipx](https://pipx.pypa.io) — an isolated app install that works
even on a PEP-668 "externally managed" system Python:

```bash
pipx install -e '.[pretty]'                       # from a local checkout
# or straight from the repo:
pipx install 'git+https://github.com/advaitsangle/llm-vulnbench.git'

vulnbench list                                    # now works from anywhere
```

Every example below then drops the `.venv/bin/python -m vulnbench.cli` prefix and
just says `vulnbench …`.

## Usage

### Quick start — just run `vulnbench`

With no arguments, vulnbench starts an **interactive session** that builds a comparative
run. It walks you through five steps, every one multi-select:

```bash
vulnbench          # ↑/↓ move · space toggle · a toggle-all · enter confirm · q cancel
```

1. **Models** — `mock`, whatever Ollama has pulled (auto-discovered), Anthropic models, or
   a spec you type.
2. **Targets** — the app catalog. Anything not yet on disk drops into the same
   point-or-install flow as `vulnbench targets`, so you never dead-end on a missing checkout.
3. **Conditions** — the ladder (B1, C1, A1, …).
4. **Knobs** — only the ones your chosen conditions actually declare.
5. **Confirm** — it prints the plan, then runs it.

It then **preflights external tools** (offering to `pip install semgrep`, to start the ZAP
daemon, or to point you at Ollama) and prints one comparative matrix: one row per
configuration, every metric as a column, best F1 starred.

```
                              vulnbench · comparative run
╭───┬────────────┬───────────────────┬──────┬──────────┬──────┬────────┬──────┬──────┬─────────┬────────╮
│   │ Target     │ Model             │ Cond │ Findings │ Prec │ Recall │   F1 │  FPR │ Latency │ Tokens │
├───┼────────────┼───────────────────┼──────┼──────────┼──────┼────────┼──────┼──────┼─────────┼────────┤
│   │ benchmark  │ —                 │ B1   │     1909 │ 0.62 │   0.59 │ 0.61 │ 0.39 │   19.1s │      0 │
│   │ benchmark  │ qwen2.5-coder:14b │ C1   │       98 │ 0.71 │   0.66 │ 0.68 │ 0.08 │  412.5s │  88000 │
│ ★ │ benchmark  │ claude-opus-4-8   │ C1   │       90 │ 0.81 │   0.74 │ 0.77 │ 0.05 │  150.0s │  91000 │
╰───┴────────────┴───────────────────┴──────┴──────────┴──────┴────────┴──────┴──────┴─────────┴────────╯
```

Pick 2 targets × 2 models × 3 conditions and you get the full comparison in one table.
Note the `—` in the model column: a **scanner-only condition runs once per target, not
once per model** — no model can change Semgrep's output, so sweeping it across models
would re-pay the scan for identical numbers. The plan tells you when it does this.

### Scripted runs — `vulnbench run`

The interactive session needs a terminal. In a script or CI, drive the same harness with
flags:

```bash
# Run a condition and score it (mock model = no server, no keys needed)
vulnbench run \
    --condition B1 C1 --source ./src \
    --ground-truth ./expectedresults-1.2.csv --kind benchmark \
    --model mock -o scorecard.json --findings-out findings.json
```

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
backend" recipe in [ARCHITECTURE.md](https://github.com/advaitsangle/llm-vulnbench/blob/main/ARCHITECTURE.md). The conditions and scoring don't change.

> **Local model on a non-default host?** The `local:` backend talks to Ollama at
> `http://localhost:11434` (Ollama's default). A custom host/port isn't a CLI flag yet —
> construct `OllamaBackend(host=...)` from Python, or run Ollama on the default address.

### Environment variables

| Variable | Used for | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | the `api:anthropic:` backend (your key) | *(required for that backend)* |
| `VULNBENCH_TARGETS_DIR` | where `vulnbench targets` installs / looks for apps | `<repo>/targets` from a checkout; `~/.vulnbench/targets` when pip-installed |
| `NO_COLOR` | disable all color and the banner | unset |

### Per-condition knobs — `--config '{...}'`

Conditions accept optional tuning knobs as a JSON object. Each condition *declares* the
knobs it understands, so the interactive session offers exactly the right ones with their
defaults filled in. On the command line, **unknown keys are silently ignored** — double-check
spelling (`max_files`, not `maxfiles`).

| Knob | Conditions | Default | Meaning |
|---|---|---|---|
| `max_files` | B3, A1 | 0 (= all) | cap on source files examined (reproducible sorted subset) |
| `max_file_bytes` | B3, C1, A1 | 60000 | per-file read cap (truncation is recorded, not silent) |
| `semgrep_ruleset` | B1, C1 | `p/owasp-top-ten` | the Semgrep config/ruleset to run |
| `semgrep_timeout` | C3 | 1800 | Semgrep timeout (s) for the authored-rules scan |
| `min_risk` | A1 | 0.0 | scout deep-dives only files it scores ≥ this (0 = all) |
| `triage`, `verify` | A1 | true | ablation toggles for the scout / verifier roles |
| `triage_head_bytes`, `triage_batch` | A1 | 1500, 10 | scout's per-file head size and files-per-batch |
| `author_files`, `author_max_bytes` | C3 | 8, 4000 | example files (and bytes each) shown to the rule author |
| `rules_out` / `rules_in` | C3 | — | author rules to a file / score with an existing rules file |
| `scan_out` / `scan_in` | C1, C2 | — | split the scanner phase from model triage (also `--scan-out`/`--scan-in`) |
| `zap_url`, `zap_api_key`, `zap_recurse`, `zap_max_wait` | B2, C2 | `http://127.0.0.1:8090`, `""`, true, 1800 | ZAP daemon connection + scan knobs |
| `zap_seed_crawler`, `zap_seed_limit` | B2, C2 | — | seed ZAP from a Benchmark crawler XML (fair DAST scoring) |
| `zap_disable_scanners` | B2, C2 | `["40026"]` | active-scan plugin ids to skip |

```bash
# 20-file slice with a bigger per-file budget
vulnbench run --condition B3 --source ./src --ground-truth gt.csv \
    --model local:qwen2.5-coder:14b --config '{"max_files": 20, "max_file_bytes": 80000}'
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
vulnbench run --condition B1 B3 C1 --source ./src \
    --ground-truth ./expectedresults-1.2.csv --model local:qwen2.5-coder:14b
```

The checkpoint is keyed on the run inputs (target, model, config, ground truth),
so changing any of them starts fresh automatically. Use `--fresh` to force a
clean run, or `--checkpoint PATH` to choose where it's stored. Interactive sweeps resume
the same way — a cell served from a checkpoint reports `resumed` instead of re-running.

### Test apps: the `targets` manager

The vulnerable apps under test are **never shipped with the repo** (they're large
and live in the gitignored `targets/` — or `~/.vulnbench/targets` for a
pip-installed vulnbench). `vulnbench targets` is an opt-in manager
for them — an arrow-key menu (↑/↓ move, space toggle, enter confirm, `q`/Ctrl-C
cancel) over a catalog defined in [`vulnbench/targets.toml`](https://github.com/advaitsangle/llm-vulnbench/blob/main/vulnbench/targets.toml):

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
checkouts keep working. The interactive session reuses this exact flow, so picking an
unlinked app there prompts you to point-or-install it on the spot.

To wire a linked app straight into a scripted run, ask for its path:

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
vulnbench run \
    --condition B1 \
    --source targets/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
    --ground-truth targets/BenchmarkJava/expectedresults-1.2.csv \
    --kind benchmark -o scorecard.json
```

> Trying it on a slice? Point `--source` at a handful of `BenchmarkTestNNNNN.java`
> files (or pass `--config '{"max_files": 20}'`). Partial runs are scored only over
> the cases they examined, so the recall number stays honest.

For the **dynamic** conditions (B2/C2) the app has to be *running*; the Docker stack
in [`deploy/`](https://github.com/advaitsangle/llm-vulnbench/blob/main/deploy/README.md) builds the BenchmarkJava WAR and a ZAP daemon for you
(`docker compose -f deploy/docker-compose.yml up --build`).

## License

[MIT](https://github.com/advaitsangle/llm-vulnbench/blob/main/LICENSE).
