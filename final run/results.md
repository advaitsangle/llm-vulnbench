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
| A2 | 100 | 0 | ast_fallback_files | 0 |
| A3 | 100 | 0 | cfg_fallback_files | 0 |
| A5 | 100 | 0 | files_full_fallback | 13 |
| A9 | 100 | 0 | candidate_parse_failures | 0 |

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
| A2 | tengyi | 106 | 0.6061 | 0.9836 | 0.75 | 1.0 | 3054.6 |
| A3 | tengyi | 102 | 0.6067 | 0.8852 | 0.72 | 0.8974 | 2236.6 |
| A4 | advait | | | | | | |
| A5 | raghav | 98 | 0.6104 | 0.7705 | 0.6812 | 0.7692 | 6263.1 |
| A6 | raghav | | | | | | |
| A7 | louis | | | | | | |
| A8 | louis | | | | | | |
| A9 | juho | 122 | 0.6061 | 0.9836 | 0.7500 | 1.0000 | 6924.3 |

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
| A2 | 60 | 39 | 1 | 0 | -0.0164 | 488040 | 22491 | 3054.2 |
| A3 | 54 | 35 | 7 | 4 | -0.0122 | 222928 | 21683 | 2236.1 |
| A4 | | | | | | | | |
| A5 | 47 | 30 | 14 | 9 | 0.0013 | 204493 | 57442 | 6262.8 |
| A6 | | | | | | | | |
| A7 | | | | | | | | |
| A8 | | | | | | | | |
| A9 | 60 | 39 | 1 | 0 | -0.0164 | 398664 | 61908 | 6923.5 |

## Provenance

| Cond | git sha | ollama | date | machine / RAM |
|------|---------|--------|------|---------------|
| B1 | 7dccfc2 | 0.30.10 | 2026-08-12 | M-series, 16 GB |
| A2 | 884565a | 0.32.9 | 2026-08-13 | Kaggle, Tesla T4 x2 (~29 GB VRAM), CUDA |
| A3 | 884565a | 0.32.9 | 2026-08-13 | Kaggle, Tesla T4 x2 (~29 GB VRAM), CUDA |
| A5 | 884565a | 0.20.7 | 2026-08-13 | Apple M1 Pro, 16 GB |
| A9 | 884565a | 0.32.5 | 2026-08-13 | Apple M3 Pro, 18 GB |

## Notes

Anything else you want to note so I can take into consideration before I write the final report :O

**A2/A3** Both look decent on F1 (0.75 / 0.72) but Youden J is negative for both. A2 has `tn=0` — it flagged every single one of the safe files as vulnerable. A3 is barely better (`tn=4`).

- **A5 (raghav):** reducer ran on 87/100 files; `files_full_fallback` = 13 (13% forwarded the
  whole file to the evaluator instead of a reduced chunk). `files_skipped_empty` = 0, no truncation.
  Reducer stats: `pruned_frac` 0.585, `chunk_fidelity` 0.945.
- A5 was run on ollama **0.20.7** (this machine, Apple M1 Pro / 16 GB), not the 0.30.10 in the B1
  row. Seed pinned (42) and model `qwen2.5-coder:14b` (ID `9ec8897f747e`) as required. Full run
  took ~104 min (6263 s) for the 100-case slice.
- A9 scanned all 100 files with no truncation, summary parse failures, candidate parse
  failures, or invalid candidates. One final verifier response failed to parse
  (`final_parse_failures = 1`). All files reached the verifier (`files_without_candidates =
  0`, `final_calls = 100`), and the run produced an FPR of 1.0.
