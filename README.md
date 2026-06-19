# vulnbench

A benchmark harness for **LLM-augmented web vulnerability detection**. It runs a
ladder of detection *conditions* — SAST, DAST, an unaided LLM, and several
LLM+scanner combinations — against the same vulnerable applications, normalizes
every result to one finding schema, and scores them the same way against known
ground truth. The goal is an apples-to-apples answer to "does the LLM actually
help, and which way of wiring it in works?"

See [`claude.md`](claude.md) for the full research design and decisions.

## The condition ladder

| id | condition | status |
|----|-----------|--------|
| B1 | Semgrep only (SAST baseline) | ✅ implemented |
| B2 | OWASP ZAP only (DAST baseline) | ✅ implemented (Docker stack in `deploy/`) |
| B3 | LLM only (unaided model reads source) | ✅ implemented |
| C1 | LLM + Semgrep output (scanner-assisted triage) | ✅ implemented |
| C2 | LLM + ZAP output (scanner-assisted triage, DAST) | 🚧 stub |
| C3 | LLM-authored Semgrep rules (LLM improves the tool) | 🚧 stub |
| A1 | Multi-agent roles (scan + verify) | 🚧 stub |

Unbuilt conditions are registered so they show in `vulnbench list` and the matrix;
each carries its intended design in its docstring.

## Architecture

Three seams keep the matrix uniform and the comparisons fair:

- **`schema.Finding`** — one normalized record (`vuln_class` CWE id, `location`,
  `confidence`, `verdict`, evidence) so a SAST `file:line` and a DAST `url/param`
  land in the same scorecard.
- **`models.ModelBackend`** — one `complete(prompt, tools?)` interface; `local:`
  (Ollama, the scored default), `api:anthropic:` (frontier ceiling), and `mock`
  (offline) backends sit behind it. Swapping the model is a flag, not a fork.
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
  conditions/          base, b1, b2, b3, c1, stubs (c2/c3/a1)
  corpus/              Target descriptor
  scoring/             metrics, benchmark CSV matcher, listmatch
  harness.py           run_one / run_matrix pipeline (+ provenance)
  report.py            colorful/animated CLI summary (rich, optional)
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

With `rich` installed (the `pretty` extra), `run` shows an animated spinner per
condition and a color-coded summary table (F1 green ≥ 0.70, yellow ≥ 0.50, red
below). The full data goes to files: `-o scorecard.json` (metrics + provenance +
trace per condition) and `--findings-out findings.json` (every normalized finding,
for FP/FN auditing). Pretty mode auto-engages on a TTY; piping or `--plain` falls
back to plain text, and without `rich` it degrades gracefully.

```
                     vulnbench · BenchmarkJava
╭──────┬──────────┬──────┬────────┬──────┬──────┬─────────┬────────╮
│ Cond │ Findings │ Prec │ Recall │  F1  │ FPR  │ Latency │ Tokens │
├──────┼──────────┼──────┼────────┼──────┼──────┼─────────┼────────┤
│ B1   │     1909 │ 0.62 │   0.59 │ 0.61 │ 0.39 │   17.9s │      0 │
╰──────┴──────────┴──────┴────────┴──────┴──────┴─────────┴────────╯
```

### Real runs

- **Semgrep** (B1/C1): `pipx install semgrep` (or `brew install semgrep`).
- **OWASP ZAP** (B2/C2): bring up the app + ZAP daemon with
  `docker compose -f deploy/docker-compose.yml up --build` (see [`deploy/`](deploy/README.md)).
- **Local model** (scored): install [Ollama](https://ollama.com), then
  `ollama pull qwen3-coder:14b` and pass `--model local:qwen3-coder:14b`.
- **Frontier ceiling**: `pip install '.[anthropic]'`, set `ANTHROPIC_API_KEY`,
  pass `--model api:anthropic:claude-opus-4-8`.

## Scoring model

Each OWASP Benchmark test case contributes one confusion-matrix cell: a case is
*detected* when the tool reports its expected CWE in that test case's file.
Metrics: precision, recall, F1, false-positive rate, and Youden's J (the
Benchmark's own score = recall − FPR), plus tokens and latency.

## Status / next

Implemented: B1, B2 (ZAP DAST, with the `deploy/` Docker stack), B3, C1, Benchmark
scoring, CLI, the model/condition/scoring seams, tests. Next per `claude.md`: C2
(LLM+ZAP triage), C3 (LLM-authored rules), A1 (multi-agent), and the realistic-app
vuln-list curation.
