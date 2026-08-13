# Final run, results

100-case slice (`final-100.csv`), 61 real / 39 safe.

Please run your condition with `final run/final_report_testing.py` (it pins the slice, the
model, and the ground truth, so everyone's rows are comparable. Calling `vulnbench` yourself
will not match). For example, to run A1 and A4 (from the repo root):

    .venv/bin/python "final run/final_report_testing.py" A1 A4

Keep the quotes, the folder name has a space. Cards land in `final run/scorecards/`. Add
your row and your cards by PR.

## Before running

- [ ] Right commit: `git fetch origin && git checkout cs453 && git pull`
- [ ] Record it: `git rev-parse --short HEAD`
- [ ] Sampling is pinned: `grep DEFAULT_SEED vulnbench/models/ollama_backend.py` prints `42`.
- [ ] Right model: `ollama list` shows `qwen2.5-coder:14b`, ID `9ec8897f747e`, 9.0 GB
- [ ] Record it: `ollama --version`
- [ ] 12 GB RAM free
- [ ] Installed: `python3 -m venv .venv && .venv/bin/pip install -e '.[pretty,structural]'`
- [ ] Corpus at `targets/BenchmarkJava`

## Before submitting a row

Commit your `card-*.json` and `fn-*.json` from `final run/scorecards/` with your PR. The
tables below are hand-copied, so the cards are the only auditable record of what produced
a row.

Read from `trace` in your scorecard.

- [ ] `files_scanned` = 100
- [ ] `truncated_files` = 0
- [ ] A2: `ast_fallback_files` = 0
- [ ] A3: `cfg_fallback_files` = 0
- [ ] A5: `files_full_fallback` low, note it
- [ ] A9: `candidate_parse_failures` low, note it

B1/B2 are scanner only, no `files_scanned` or `truncated_files`.

| Cond | files_scanned | truncated | fallback | value |
|------|--------------:|----------:|----------|------:|
| B1 | n/a | n/a | | |
| A6 | 100 | 0 | files_judged_code_only=0 | overhead 0.332 |

## Scorecard: from the terminal summary

| Cond | Who | Findings | Prec | Recall | F1 | FPR | Latency |
|------|-----|---------:|-----:|-------:|-----:|----:|--------:|
| B1 | advait | 73 | 0.7091 | 0.6393 | 0.6724 | 0.4103 | 4.2 |
| B2 | advait | | | | | | |
| B3 | advait | | | | | | |
| C1 | advait | | | | | | |
| C2 | advait | | | | | | |
| C3 | advait | | | | | | |
| A1 | advait | | | | | | |
| A2 | tengyi | | | | | | |
| A3 | tengyi | | | | | | |
| A4 | advait | | | | | | |
| A5 | raghav | | | | | | |
| A6 | raghav | 107 | 0.6042 | 0.9508 | 0.7389 | 0.9744 | 7130.9 |
| A7 | louis | | | | | | |
| A8 | louis | | | | | | |
| A9 | juho | | | | | | |

## Scorecard: only in `card-<COND>-<timestamp>.json`

`tp/fp/fn/tn` and `youden_j` under `metrics`, rest top level.

| Cond | TP | FP | FN | TN | Youden J | input_tokens | output_tokens | model_seconds |
|------|---:|---:|---:|---:|---------:|-------------:|--------------:|--------------:|
| B1 | 39 | 16 | 22 | 23 | 0.2291 | 0 | 0 | 0.0 |
| B2 | | | | | | | | |
| B3 | | | | | | | | |
| C1 | | | | | | | | |
| C2 | | | | | | | | |
| C3 | | | | | | | | |
| A1 | | | | | | | | |
| A2 | | | | | | | | |
| A3 | | | | | | | | |
| A4 | | | | | | | | |
| A5 | | | | | | | | |
| A6 | 58 | 38 | 3 | 1 | -0.0235 | 282556 | 59003 | 7130.5 |
| A7 | | | | | | | | |
| A8 | | | | | | | | |
| A9 | | | | | | | | |

## Provenance

| Cond | git sha | ollama | date | machine / RAM |
|------|---------|--------|------|---------------|
| B1 | 7dccfc2 | 0.30.10 | 2026-08-12 | M-series, 16 GB |
| A6 | 884565a | 0.20.7 | 2026-08-13 | M-series (M1 Pro), 16 GB |

## Notes

Anything else you want to note so I can take into consideration before I write the final report :O

**A6 (raghav):** clean run — `files_scanned`=100, `truncated_files`=0, `summaries_truncated`=0,
`summary_parse_failures`=0, `files_judged_code_only`=0, `files_skipped_malformed`=0. So every
one of the 100 files got a real structural summary before the judge; no file degraded to
code-only B3. `model_calls`=200 (100 summary + 100 judge), `summary_overhead_frac`=0.332 (the
summary added ~33% on top of the code going into the judge).

- `judge_parse_failures`=3: on 3 files the judge's reply had no parsable findings object
  (counted apart from "found nothing"). Those files still counted in the denominator — with
  tn=1 and fpr≈0.97, A6 flags almost everything, so this doesn't dent recall but is worth a line.
- Provenance caveat: HEAD at run time was `884565a`, but the A6 files (`vulnbench/conditions/a6_summarize.py`)
  were still **uncommitted** on branch `A6-test-results` — not on the pinned `cs453` commit. The
  card is the authoritative record; re-run after A6 lands on `cs453` if you want a sha that
  reproduces exactly.
