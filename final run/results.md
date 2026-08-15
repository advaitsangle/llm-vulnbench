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
| B2 | n/a | n/a | seeded_requests | 100 |
| B3 | 100 | 0 | | |
| C1 | 100 | 0 | semgrep_raw_findings=73, files_reviewed=59 | |
| C2 | n/a | n/a | endpoints_reviewed | 100 |
| A1 | 100 | 0 | files_skipped_by_scout | 0 |
| A4 | 100 | 0 | top1_leak_match_frac | 0.96 |
| A2 | 100 | 0 | ast_fallback_files | 0 |
| A3 | 100 | 0 | cfg_fallback_files | 0 |
| A5 | 100 | 0 | files_full_fallback | 13 |
| A6 | 100 | 0 | files_judged_code_only=0 | overhead 0.332 |
| A7 | 100 | 0 | shots=4 | |
| A8 | 100 | 0 | cot_followed=98/100 | |
| A9 | 100 | 0 | candidate_parse_failures | 0 |

## Scorecard: from the terminal summary

| Cond | Who | Findings | Prec | Recall | F1 | FPR | Latency |
|------|-----|---------:|-----:|-------:|-----:|----:|--------:|
| B1 | advait | 73 | 0.7091 | 0.6393 | 0.6724 | 0.4103 | 2.6 |
| B2 | advait | 944 | 1.0000 | 0.2951 | 0.4557 | 0.0000 | 82.4 |
| B3 | advait | 93 | 0.6279 | 0.8852 | 0.7347 | 0.8205 | 5611.1 |
| C1 | advait | 67 | 0.7193 | 0.6721 | 0.6949 | 0.4103 | 3836.7 |
| C2 | advait | 229 | 0.5897 | 0.3770 | 0.4600 | 0.4103 | 9145.5 |
| C3 | — | dropped | | | | | |
| A1 | advait | 97 | 0.6421 | 1.0000 | 0.7821 | 0.8718 | 12615.9 |
| A2 | tengyi | 106 | 0.6061 | 0.9836 | 0.75 | 1.0 | 3054.6 |
| A3 | tengyi | 102 | 0.6067 | 0.8852 | 0.72 | 0.8974 | 2236.6 |
| A4 | advait | 101 | 0.6354 | 1.0000 | 0.7771 | 0.8974 | 7829.1 |
| A5 | raghav | 98 | 0.6104 | 0.7705 | 0.6812 | 0.7692 | 6263.1 |
| A6 | raghav | 107 | 0.6042 | 0.9508 | 0.7389 | 0.9744 | 7130.9 |
| A7 | louis | 100 | 0.6489 | 1.0000 | 0.7871 | 0.8462 | 2123.4 |
| A8 | louis | 100 | 0.6333 | 0.9344 | 0.7550 | 0.8462 | 2761.0 |
| A9 | juho | 122 | 0.6061 | 0.9836 | 0.7500 | 1.0000 | 6924.3 |

## Scorecard: only in `card-<COND>-<timestamp>.json`

`tp/fp/fn/tn` and `youden_j` under `metrics`, rest top level.

| Cond | TP | FP | FN | TN | Youden J | input_tokens | output_tokens | model_seconds |
|------|---:|---:|---:|---:|---------:|-------------:|--------------:|--------------:|
| B1 | 39 | 16 | 22 | 23 | 0.2291 | 0 | 0 | 0.0 |
| B2 | 18 | 0 | 43 | 39 | 0.2951 | 0 | 0 | 0.0 |
| B3 | 54 | 32 | 7 | 7 | 0.0647 | 131606 | 22651 | 5611.0 |
| C1 | 41 | 16 | 20 | 23 | 0.2619 | 83517 | 14117 | 3520.2 |
| C2 | 23 | 16 | 38 | 23 | -0.0332 | 141806 | 48034 | 9145.4 |
| C3 | — | — | — | — | dropped | — | — | — |
| A1 | 61 | 34 | 0 | 5 | 0.1282 | 308433 | 49075 | 12615.4 |
| A2 | 60 | 39 | 1 | 0 | -0.0164 | 488040 | 22491 | 3054.2 |
| A3 | 54 | 35 | 7 | 4 | -0.0122 | 222928 | 21683 | 2236.1 |
| A4 | 61 | 35 | 0 | 4 | 0.1026 | 390511 | 22147 | 7827.7 |
| A5 | 47 | 30 | 14 | 9 | 0.0013 | 204493 | 57442 | 6262.8 |
| A6 | 58 | 38 | 3 | 1 | -0.0235 | 282556 | 59003 | 7130.5 |
| A7 | 61 | 33 | 0 | 6 | 0.1538 | 345906 | 21961 | 2123.3 |
| A8 | 57 | 33 | 4 | 6 | 0.0883 | 158306 | 35978 | 2760.9 |
| A9 | 60 | 39 | 1 | 0 | -0.0164 | 398664 | 61908 | 6923.5 |

## Provenance

| Cond | git sha | ollama | date | machine / RAM |
|------|---------|--------|------|---------------|
| B1 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| B2 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| B3 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| C1 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| C2 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| A1 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| A4 | c2b2b4a | 0.30.10 | 2026-08-14 | MacBook Air M4, 16 GB |
| A2 | c7846e8 | 0.32.9 | 2026-08-13 | Kaggle, Tesla T4 x2 (~29 GB VRAM), CUDA |
| A3 | c7846e8 | 0.32.9 | 2026-08-13 | Kaggle, Tesla T4 x2 (~29 GB VRAM), CUDA |
| A5 | c7846e8 | 0.20.7 | 2026-08-13 | Apple M1 Pro, 16 GB |
| A6 | c7846e8 | 0.20.7 | 2026-08-13 | M-series (M1 Pro), 16 GB |
| A7 | c7846e8 | 0.9.0 | 2026-08-13 | M-series, 24 GB |
| A8 | c7846e8 | 0.9.0 | 2026-08-13 | M-series, 24 GB |
| A9 | c7846e8 | 0.32.5 | 2026-08-13 | Apple M3 Pro, 18 GB |

## Notes

Anything else you want to note so I can take into consideration before I write the final report :O

**advait's rows (B1, B2, B3, C1, C2, A1, A4).**

- **A4 leak metrics:** `top1_leak_match_frac` = 0.96 (the retriever's top hit matched the category
  the corpus leaks, 96 of 100 files), `findings_echoing_top1_frac` = 0.9125 (91% of findings repeated
  that top-ranked CWE). A4's recall of 1.000 should be read against these.
- **B3, C1, C2, A1, A4 ran one test case at a time** via `run_incremental.py` (cards say so in
  `trace.driver`). Per-case output was verified identical to a whole-slice run before the sweep.
  A1 and A4 ran in chunks of 10 because A1's scout rates 10 files per prompt and A4 evicts its
  embedding model before the judge loads.
- **C2's 9145 s covers the 100 scoreable endpoints only.** 396 of 959 alerts sit on category
  directories (`/benchmark/cmdi-00`) that name no test case; findings there cannot score, so they were
  not triaged.
- **C3 dropped.** LLM-authored Semgrep rules scored F1 0.00 in earlier runs: valid Semgrep, but they
  only matched `.executeQuery` and required the taint source inside the sink call, which holds in
  0 of 80 held-out files. Measured-not-viable, not untested.
- B1's latency is 2.6 s, from a re-run today that produced the card behind this row; metrics are
  unchanged from the original 4.2 s run.
- **`crawler-100.xml` and `zap-alerts-100.json` are committed next to the cards** because neither
  DAST row reproduces without them: ZAP active scans are timing-dependent, so the seed requests and
  the exact 959-alert scan C2 triaged (B2's own card records 944) cannot be regenerated.

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

**A6 (raghav):** clean run — `files_scanned`=100, `truncated_files`=0, `summaries_truncated`=0,
`summary_parse_failures`=0, `files_judged_code_only`=0, `files_skipped_malformed`=0. So every
one of the 100 files got a real structural summary before the judge; no file degraded to
code-only B3. `model_calls`=200 (100 summary + 100 judge), `summary_overhead_frac`=0.332 (the
summary added ~33% on top of the code going into the judge).

- `judge_parse_failures`=3: on 3 files the judge's reply had no parsable findings object
  (counted apart from "found nothing"). Those files still counted in the denominator — with
  tn=1 and fpr≈0.97, A6 flags almost everything, so this doesn't dent recall but is worth a line.
- Provenance caveat: HEAD at run time was `c7846e8`, but the A6 files (`vulnbench/conditions/a6_summarize.py`)
  were still **uncommitted** on branch `A6-test-results` — not on the pinned `cs453` commit. The
  card is the authoritative record; re-run after A6 lands on `cs453` if you want a sha that
  reproduces exactly.
