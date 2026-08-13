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
| A7 | 100 | 0 | shots=4 | |
| A8 | 100 | 0 | cot_followed=98/100 | |

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
| A6 | raghav | | | | | | |
| A7 | louis | 100 | 0.6489 | 1.0000 | 0.7871 | 0.8462 | 2123.4 |
| A8 | louis | 100 | 0.6333 | 0.9344 | 0.7550 | 0.8462 | 2761.0 |
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
| A6 | | | | | | | | |
| A7 | 61 | 33 | 0 | 6 | 0.1538 | 345906 | 21961 | 2123.3 |
| A8 | 57 | 33 | 4 | 6 | 0.0883 | 158306 | 35978 | 2760.9 |
| A9 | | | | | | | | |

## Provenance

| Cond | git sha | ollama | date | machine / RAM |
|------|---------|--------|------|---------------|
| B1 | 7dccfc2 | 0.30.10 | 2026-08-12 | M-series, 16 GB |
| A7 | 884565a | 0.9.0 | 2026-08-13 | M-series, 24 GB |
| A8 | 884565a | 0.9.0 | 2026-08-13 | M-series, 24 GB |

## Notes

Anything else you want to note so I can take into consideration before I write the final report :O