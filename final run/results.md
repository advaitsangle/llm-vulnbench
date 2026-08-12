# Final run, results

100-case slice (`final-100.csv`), 61 real / 39 safe. Add your row by PR.

## Before running

- [ ] Right commit: `git fetch origin && git checkout cs453 && git pull`
- [ ] Record it: `git rev-parse --short HEAD`
- [ ] Right model: `ollama list` shows `qwen2.5-coder:14b`, ID `9ec8897f747e`, 9.0 GB
- [ ] Record it: `ollama --version`
- [ ] 12 GB RAM free
- [ ] Installed: `python3 -m venv .venv && .venv/bin/pip install -e '.[pretty,structural]'`
- [ ] Corpus at `targets/BenchmarkJava`

## Before submitting a row

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
| A6 | | | | | | | | |
| A7 | | | | | | | | |
| A8 | | | | | | | | |
| A9 | | | | | | | | |

## Provenance

| Cond | git sha | ollama | date | machine / RAM |
|------|---------|--------|------|---------------|
| B1 | 7dccfc2 | 0.30.10 | 2026-08-12 | M-series, 16 GB |

## Notes

Anything else you want to note so I can take into consideration before I write the final report :O