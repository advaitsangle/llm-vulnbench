# Planning & Research Notes (internal)

Working notes behind `proposal.tex`. Purpose: (1) hold the research depth that won't
fit a 1-page proposal so it's ready for the 7-10 page report, and (2) catalog tools,
frameworks, and decisions for the agentic build. This is **not** a duplicate of the
proposal; it only records new detail, side notes, and decisions.

Status: living doc. Last updated during task #3 (tooling + LLM strategies).

---

## ⚑ ITEMS FOR THE TEAM TO LOOK UP / CONFIRM

These need a human. Nothing here is decided.

1. ~~`llmsast` citation.~~ **RESOLVED.** Koterba, Łukaczyk, Książek,
   *Information and Software Technology*, 2026, doi:10.1016/j.infsof.2026.108213
   (open access, CC BY-NC). Key numbers: Semgrep F1 0.66 vs best LLM (Gemini 3
   Pro) 0.88 on OWASP Benchmark v1.2 + external set. Important: it tests LLMs as
   a **replacement** for Semgrep, not in combination. So our differentiation is
   the C1/C2/C3 combinations and the DAST half, not LLM-vs-Semgrep substitution
   (they already did that). Our B1-vs-B3 cells partly replicate them; frame as
   grounding, not novelty.
2. ~~`webllm` citation.~~ **RESOLVED.** Gaikwad, Kulkarni, Deshmukh, Mehta,
   Akolkar, "Penetration Testing for Websites using LLM," Research Square
   preprint, 2026, doi:10.21203/rs.3.rs-9937475/v1 (CC BY). Still a preprint, but
   more relevant than first thought: it uses a **local Qwen 2.5 7B via Ollama**,
   constrains the LLM to **post-scan reasoning (no direct tool calls)**, and
   concludes a **constrained assistant beats an autonomous agent** — independent
   support for demoting our A1. Detection-aligned (triage/analysis), not
   exploitation, despite the "pentest" name.
3. ~~Exact RAM of the team's M4 MacBooks.~~ **RESOLVED: 16 GB.** Drives the
   local-model choice to the ~14B tier (see Models). One unknown remains: do
   the other four teammates' machines match, since scored runs must use one
   machine/model.
4. ~~Claude / OpenAI budget.~~ **RESOLVED: Claude Pro available.** Important
   caveat: Claude Pro is an *interactive* subscription (Claude Code / Desktop),
   **not** API access. It cannot easily batch across the thousands of Benchmark
   test cases. So a Claude "ceiling" run is realistic only on a small hand-picked
   subset or on the realistic apps, reported as illustrative headroom, not a full
   scored sweep. NEW LOOKUP: if we want a full-Benchmark frontier run, we need
   API credits (Anthropic or OpenAI) — decide whether that's worth buying.
5. ~~Course deadlines.~~ **RESOLVED.** Midterm report Jul 17, presentation
   Jul 30, final report Aug 14. Timeline in the proposal now spans to Aug 14.
6. **Target-app decision (#7)**: which apps beyond OWASP Benchmark. Candidates surfaced:
   WebGoat, DVWA, bWAPP (all used as baselines in the `webllm` paper), plus Juice Shop.
   See "Corpus / datasets" for the scoring catch.
7. **Verify the headline stat** used in the intro (LLMs detect ~90-100% of vulns but with
   high false positives) against the `ensemble` paper (arXiv:2407.16235) before final.
8. **"Mythos" note**: resolved for now by anchoring the intro on the `ensemble` result.
   If a specific paper was meant, supply it.

---

## Report-depth notes (for the 7-10 page expansion)

Keyed to proposal sections. Only the extra material that got cut for length.

### Introduction / motivation
- The recall-vs-false-positive tension is the spine of the whole report. Concrete numbers
  to use: the `ensemble` study (arXiv:2407.16235) compares 15 SAST tools vs 12 LLMs across
  Java/C/Python and reports SAST = low detection / low FP, LLMs = very high detection (up
  to ~90-100%) / high FP, and ensembling recovers some of both. That is the quantitative
  hook.
- IRIS gives a clean single-number contrast for the report: on CWE-Bench-Java, CodeQL
  detects 27 vulns, IRIS+GPT-4 detects 55, with a lower false-discovery rate
  (arXiv:2405.17238). Good for a "LLM augmentation can raise recall without wrecking
  precision" point.

### Related work (expansion plan)
Group the cited work into three buckets when we expand:
- **LLM-augmented SAST**: LLM4SA (Wen et al., ACM TKDD 2024; ~81% precision filtering SAST
  warnings, evaluated on Juliet + real C/C++), IRIS (ICLR 2025, LLM+CodeQL neuro-symbolic),
  ZeroFalse (arXiv:2510.02534; flow-sensitive traces + CWE context).
- **Cross-approach comparisons**: `ensemble` (arXiv:2407.16235), `llmsast`
  (LLMs vs Semgrep on OWASP Benchmark, with cost/latency).
- **Integration-strategy / agentic**: Sifting the Noise (arXiv:2601.22952; agentic
  frameworks do NOT consistently beat plain prompting for SAST FP filtering — important,
  tempers our A1 expectations). DAST side: `webllm` (LLM atop scanners, F1 0.58 -> 0.82,
  false alarms 23.4% -> 7.2% on WebGoat/DVWA/bWAPP).
- Side note on scope discipline: keep related work on **detection** (codebase review +
  black-box detection), not **exploitation** (pentest/CTF/getting shells). XBOW,
  PentestGPT v2, CheckMate, CVE-Bench are exploitation and were deliberately excluded.

### Methodology (things to spell out in the report that the proposal compresses)
- Why the head-to-head is fair: OWASP Benchmark scores SAST, DAST, and IAST against the
  **same** ground truth (`expectedresults-1.2.csv`, one intended CWE per test case marked
  T/F positive). This is the linchpin and deserves a paragraph.
- Threats to validity to pre-empt: overfitting prompts/rules to the Benchmark (see
  Overfitting note), single-model fairness, Benchmark v1.2 being synthetic vs real-app
  generalization (hence the secondary realistic apps).

---

## Engineering & agentic build catalog

### Corpus / datasets
- **OWASP Benchmark** is the scored backbone. Key facts:
  - Fully runnable vulnerable web app; every test case maps to one CWE, labeled T/F positive.
  - Scorable by **SAST, DAST (explicitly ZAP), and IAST** with the **same** ground truth.
  - Comes in **Java** (most mature, most scorecard generators) and **Python** versions.
    There is **no JS version**.
  - Scoring + DAST crawling tooling lives in **BenchmarkUtils**
    (github.com/OWASP-Benchmark/BenchmarkUtils) — gives precision/recall/F-score
    scorecards automatically. This is why metrics are feasible (answers an earlier
    feasibility worry).
- **Scoring catch (decision needed):** Juice Shop / WebGoat / DVWA / bWAPP are realistic
  apps but are **not** OWASP-Benchmark-scorecard compatible. Juice Shop is JS/Node and has
  its own challenge/solution ground truth, not Benchmark CSV. So:
  - Rigorous auto-scored matrix -> OWASP Benchmark (Java primary; Python optional).
  - Realistic secondary targets (qualitative or hand-labeled) -> Juice Shop / WebGoat / DVWA.
  - We should NOT pretend Juice Shop is auto-scored. Either hand-label a subset or use it
    only for narrative/realism.

### SAST tool (decision: Semgrep primary)
- **Semgrep**: covers Java + Python + JS/TS, 5000+ rules, fast, deterministic, used as the
  baseline in the `llmsast` and other comparison papers (good for comparability). Official
  MCP server exists (see below). Primary choice.
- **CodeQL**: stronger interprocedural taint (this is what IRIS builds on). Heavier, slower,
  GitHub-oriented. Candidate as a *second* SAST if time allows, to strengthen the static
  baseline and mirror IRIS.
- **SonarQube / Snyk Code**: both have MCP servers; not needed unless we want a third SAST
  point. Snyk official MCP = 11 tools.

### DAST tool (decision: OWASP ZAP)
- **OWASP ZAP**: free, OWASP Benchmark ships a ZAP scorecard generator, has a full REST API
  + daemon mode for automation, integrates into CI. Active scan sends attack-mimicking
  requests; must run against a non-prod target. Primary choice.
- **Burp Suite**: stronger manual tooling, pro-oriented. Not needed for an automated matrix.

### LLM strategies to test (this is the "experiment a lot" surface)
Organized from cheapest to most involved:
1. **Prompting variants** (B3 family): zero-shot, few-shot, chain-of-thought, and
   RAG-with-CWE-context. Cheap to vary; the LLM4SA/ZeroFalse results suggest CWE context
   matters a lot.
2. **Scanner-assisted / triage** (C1, C2): feed Semgrep or ZAP findings to the LLM to
   confirm/triage/suppress false positives. This is the LLM4SA pattern and likely our
   highest-value cell.
3. **Agentic / tool-driving** (A1): LLM calls the scanners as tools over multiple steps,
   decides what to scan next, re-runs, reasons over combined output. Note Sifting the Noise:
   agentic may NOT beat #2, so treat as a hypothesis, not an assumption.
4. **Skills / harness tweaks**: e.g., a Semgrep "skill" that standardizes how findings are
   summarized for the model. Low effort, possibly meaningful.

### Agent frameworks / MCP integrations (so we don't build from scratch)
- **Semgrep official MCP server** (`github.com/semgrep/mcp`, also `semgrep.dev/docs/mcp`):
  6 tools — scan, AST, custom-rule creation, language detection, etc. Works with Claude
  Code, Cursor, any MCP client. stdio / streamable-HTTP / SSE; Docker image at
  `ghcr.io/semgrep/mcp`. There's also a Semgrep **plugin** bundling MCP + hooks + skills.
- **DevSecOps-MCP**: bundles Semgrep, Bandit, SonarQube, **OWASP ZAP**, Trivy as MCP tools
  (SAST/DAST/IAST/SCA in one). The cleanest single source for a ZAP MCP tool. (DAST MCP
  coverage is otherwise thin.)
- **ZAP via its own REST API**: most controllable path for the agent if MCP wrapping is
  flaky — spider/active-scan/alerts endpoints in daemon mode.
- **Agent runtimes to consider**: Claude Code / Claude Agent SDK (native MCP + tool-calling,
  matches the Carta angle), LangGraph, OpenHands, SWE-agent, AutoGen, CrewAI. Sifting the
  Noise specifically benchmarked Aider / OpenHands / SWE-agent, so those are defensible
  precedents to cite if we pick one.

### Models (size to the M4 RAM — confirm RAM first, item #3)
Current (2026) local-on-Mac picks via Ollama/MLX:
- **16 GB**: Qwen3-Coder ~14B (Q4) or GPT-OSS 20B or DeepSeek-R1 14B. Usable, weaker on
  multi-step agentic.
- **24 GB (M4 Pro)**: Qwen3-Coder 30B-A3B MoE (Q4, ~17 GB, ~30-35 tok/s) is the current
  sweet spot; or Qwen2.5-Coder 32B.
- **32 GB+**: Llama 3.3 70B class becomes viable; closes more of the gap to cloud.
- Reality check: local models are weakest exactly where our agentic cell lives (long
  multi-step tool use). Frontier cloud (Claude Opus/Sonnet) still leads on complex chains.
- **Fairness rule**: all *officially scored* runs use ONE model on ONE machine. Suggest a
  local Qwen-Coder as the standard scored model (cost-free, reproducible), plus an optional
  Claude/Opus "ceiling" run on the agentic cell to show the headroom. That ceiling run is
  reported separately, not mixed into the scored comparison.

### Evaluation / matrix design
- Conditions: B1 Semgrep, B2 ZAP, B3 LLM, C1 LLM+Semgrep, C2 LLM+ZAP, A1 agentic
  (from proposal) + the prompting variants above as sub-rows where they matter.
- Metrics: precision, recall, F1, false-positive rate (all from BenchmarkUtils), plus
  cost (tokens / $ per run) and latency (wall-clock). The last two are what make this an
  *engineering* evaluation, not just an accuracy table.
- Fixed factors for scored runs: Benchmark version (v1.2), one model, one machine, fixed
  scanner versions, fixed prompt per condition.

### Overfitting / benchmark-gaming (#6)
- Risk: tuning prompts or Semgrep rules until they ace OWASP Benchmark, then reporting
  inflated numbers. The `ensemble`/`llmsast` papers exist partly because OWASP Benchmark is
  synthetic and gameable.
- Mitigations to design in: do not tune on the scored split; hold out a portion of Benchmark
  test cases, or use the Python Benchmark as a held-out second corpus, or validate the best
  config on a realistic app (Juice Shop subset) it was never tuned on. Report tuned vs
  held-out numbers separately.

---

## Open design decisions (status)

- **#3 tooling**: leaning Semgrep (SAST) + ZAP (DAST) + the strategy ladder above. Semgrep
  MCP + ZAP REST/DevSecOps-MCP make the agentic cell tractable. CodeQL optional second SAST.
- **#4 feasibility**: largely de-risked — OWASP Benchmark auto-scores SAST+DAST on shared
  ground truth; metrics are computable; agent tooling exists. Remaining risk is the agentic
  cell's reliability and local-model strength.
- **#5 models**: pending RAM + budget (items #3, #4 above).
- **#6 overfitting**: plan sketched above; needs a held-out corpus decision.
- **#7 target apps**: OWASP Benchmark (Java +/- Python) scored; Juice Shop/WebGoat/DVWA as
  realistic secondary, with the scoring catch noted.

---

## Update — task #4 (harness, feasibility, models, overfitting, agentic)

### Corpus split: RESOLVED
OWASP Benchmark = the auto-scored backbone. Realistic apps (Juice Shop, WebGoat,
DVWA) = secondary, qualitative. Now in the proposal.

### Qualitative scoring without per-run manual QA (answers "do I have to verify by hand?")
No, not per run. The manual work is a one-time setup per app, then scoring is automated.
- **One-time per app:** build a ground-truth vuln list. Juice Shop exposes a
  machine-readable challenge catalog (100+ challenges, with categories/locations);
  WebGoat and DVWA have documented per-lesson vulnerabilities. So the list is curated
  from the app's own data, not invented.
- **Per run (automated):** a harness normalizes every condition's output to
  (CWE/vuln-class + location: file or URL/endpoint/param), then auto-matches against the
  list and computes the same metrics. "Which approach found the most" becomes a count
  against the list, not a human judgment.
- **Honest limits:** matching is fuzzier than OWASP Benchmark's exact T/F labels (a
  finding's location/class has to be mapped to a known vuln), so secondary-app numbers are
  approximate by design — which is exactly why they're labeled qualitative. Occasional
  spot-checking of ambiguous matches is the only recurring manual touch.
- **Watch out:** Juice Shop's built-in *scoreboard* measures *exploitation* (challenge
  solved), not *detection* (scanner/LLM flagged it). Use the challenge catalog as a vuln
  list; do NOT use scoreboard completion as the detection metric.

### Models: RESOLVED for 16 GB
- Scored local model: **Qwen3-Coder ~14B (Q4_K_M)** is the daily-driver pick at 16 GB
  (GPT-OSS 20B is borderline/tight with context). This is the single fixed model for all
  *scored* runs (reproducible, free).
- **Claude Pro = ceiling only, not the scored model.** Use it interactively (Claude Code)
  on a small subset or the realistic apps to show frontier headroom, reported separately.
  Full-Benchmark frontier numbers would need API credits (see lookup #4).

### Overfitting (answers the concern directly)
We are not training a model, so the overfitting risk is narrow: tuning prompts or Semgrep
rules until they ace OWASP Benchmark, then reporting inflated numbers. Plan:
1. **Freeze prompts/rules before scored runs.** Do not iterate against the scored split.
2. **Hold out a split**, or use the **Python Benchmark** as a held-out second corpus
   (different language, same labeling scheme), and report tuned vs held-out separately.
3. **Validate the best config on the realistic apps** it was never tuned on.
4. **Caveat to state in the report:** OWASP Benchmark is public and synthetic, so existing
   tools may be implicitly tuned to it; our held-out and realistic-app numbers are the
   honest signal, the Benchmark numbers are the comparable-to-prior-work signal.

### "How does an LLM actually drive the scanners?" (+ ambiguity flagged)
Concretely: the agent is given tools (functions) like `run_semgrep(path)`,
`run_zap_scan(url)`, `get_findings()`. It issues a tool call, reads the JSON result,
decides the next step (e.g., "Semgrep flagged possible SQLi in login route -> run a
targeted ZAP active scan on /login to confirm"), and synthesizes a final verdict. The
Semgrep MCP server and ZAP's REST API expose exactly these; the agent runtime (e.g.
Claude Code) handles the loop. So mechanically it is feasible.
**But the skepticism is warranted, so this is flagged as AMBIGUITY TO RESOLVE:**
- On OWASP Benchmark (thousands of tiny, near-identical test cases) per-case agentic
  orchestration is expensive and probably no better than just running the scanner. Agentic
  value, if any, shows up on a *realistic* app where exploration and triage matter.
- Sifting the Noise found agentic frameworks don't reliably beat plain prompting.
- Claude Pro can't automate it at scale (no API).
- **Recommendation to decide as a team:** make scanner-assisted triage (C1/C2) the core LLM
  contribution; treat agentic-driving (A1) as a *stretch demo on the realistic apps*, not a
  full scored condition. The proposal now phrases agentic as "exploratory" to match.

### End-to-end harness / feasibility (#4)
Pipeline per (app, condition):
1. Deploy target (Docker: Benchmark, Juice Shop, WebGoat, DVWA).
2. Run the condition: scanner CLI/API, or LLM call, or LLM+scanner-output, or agent loop.
3. Normalize output to a common finding schema (class + location + confidence).
4. Score: BenchmarkUtils scorecard for Benchmark; list-matching harness for the rest.
5. Log cost (tokens/$) and latency (wall-clock) alongside accuracy.
- **De-risked:** Benchmark auto-scores SAST+DAST on shared ground truth; scanners have
  CLIs/APIs and MCP servers; metrics are computable; secondary-app scoring is automatable
  after one-time list curation.
- **Remaining feasibility risks:** agentic cell reliability + cost; Claude Pro automation
  ceiling; fuzzy matching quality on secondary apps; building the common finding schema so
  SAST (file:line) and DAST (URL/param) findings are comparable.

### Open decisions — updated status
- **#4 feasibility/harness:** largely designed (above). Open: the common finding schema and
  whether A1 is a scored condition or a stretch demo.
- **#5 models:** RESOLVED (Qwen3-Coder 14B scored; Claude Pro ceiling). Open: API credits.
- **#6 overfitting:** plan set (above). Open: pick the held-out corpus (Python Benchmark vs
  a held-out split).
- **#7 target apps:** Benchmark (Java; Python as held-out candidate) + Juice Shop/WebGoat/
  DVWA qualitative. Settled enough to proceed.

---

## Update — resolving remaining items + Semgrep configs, rule authoring, harness vision

### Semgrep is configurable, and yes, AI can write its rules (NEW strategy: C3)
- Semgrep behaves very differently by config: rulesets via `--config` (`p/default`,
  `p/owasp-top-ten`, `p/security-audit`, `--config auto`), custom YAML rules, and
  taint-mode rules. So the "Semgrep only" baseline is itself a config choice — fix one
  standard ruleset for B1 and document it.
- **LLM rule authoring is supported and tractable.** Semgrep's MCP server exposes custom
  rule creation/validation, and "LLM-augmented rule authoring" is a documented use case.
  New condition **C3 = LLM writes/refines Semgrep rules, then Semgrep runs them
  deterministically.** This is better than runtime agentic orchestration for us: the LLM
  cost is paid once (offline), the scan stays deterministic and reproducible, and it runs
  cleanly on Benchmark. It directly tests "can the LLM make the existing tool better"
  rather than "can the LLM replace the tool." Added to the proposal.
- Watch for overfitting here especially: if the LLM authors rules against Benchmark, that
  is textbook benchmark-gaming. Generate/refine rules on a tuning split or a different app,
  then score on the held-out split (see overfitting plan).

### Harness vision (the ultimate target architecture)
Single harness, pluggable model backend:
- `--model local:<ollama-model>` (default for scored runs, e.g. qwen3-coder:14b) OR
  `--model api:<provider>` with a user-supplied API key (Anthropic/OpenAI).
- Same conditions (B1..C3, A1) run against whichever backend is selected, so the
  local-vs-frontier comparison becomes a first-class feature, not a separate experiment.
- This is now reflected in the proposal's Proposed Work. Implementation note: wrap each
  backend behind one `complete(prompt, tools?)` interface so conditions don't care which
  model they're talking to.

### Common finding schema: DEFINED
Every condition emits findings normalized to:
`{ vuln_class (CWE id), location, confidence, source_condition }`
- `location` = `file:line` for SAST, `URL + method + param` for DAST, `test-case id` for
  Benchmark (Benchmark already pins this).
- Benchmark scoring uses BenchmarkUtils against `expectedresults-1.2.csv` directly.
- Secondary-app scoring matches `(vuln_class, location)` against the curated per-app list,
  with fuzzy location matching (same endpoint/param, or same file/region).
- This schema is what makes SAST (file:line) and DAST (URL/param) findings comparable in
  one table — it was the main open feasibility risk and is now pinned.

### Other open items: RESOLVED / dispositioned
- **A1 scored vs demo:** DECIDED — A1 is a stretch demo on the realistic apps, not a scored
  Benchmark condition. C3 takes over as the tractable "LLM improves the tool" condition.
- **Held-out corpus (#6):** DECIDED — Benchmark Java = primary scored; Benchmark Python =
  held-out second corpus (same labeling scheme, different language). Realistic apps =
  external check.
- **API credits:** DEPRIORITIZED — Claude Pro ceiling on a subset is enough; only buy API
  credits if a full-Benchmark frontier sweep is wanted later.
- **Title (#8):** settled ("Benchmarking LLM-Augmented Web Vulnerability Detection").
- **Dates (#8):** still a team lookup — only the July 30 presentation is known; midterm/
  final report dates need the course schedule.

### Remaining true unknowns (team, not me)
1. Whether to spend on API credits for a full-Benchmark frontier sweep (optional;
   Claude Pro ceiling on a subset is the default).

Everything else (dates, RAM, both citations) is now resolved. Teammates' machines
confirmed at 16 GB or comparable, so the local-model and one-machine/one-model plan holds.

---

## Design templates worth borrowing from the two papers

From **Gaikwad et al. (`webllm`)** — a near-blueprint for our harness/eval:
- Strict JSON output schema for the LLM: `{candidate_cwe, verdict
  (confirmed|candidate|not_supported), confidence, evidence, counter_evidence,
  remediation, requires_human_review}`. Good basis for our common finding schema.
- Temperature 0.1 (they measured 0.7 -> 31% fabrication, 0.1 -> 12%). Use low temp.
- Evidence-grounded verdicts: model must cite supporting + disconfirming evidence; this
  is how they cut hallucination from 18.6% to 7.2% post-filter.
- Stats: McNemar's test for detection differences, Wilcoxon signed-rank for time
  differences. We can reuse this for our trade-off comparisons.
- Component ablation (which LLM role adds what) — response interpretation was the biggest
  detection gain, explanation generation mostly helped humans. Worth replicating.
- Their constrained-assistant > autonomous-agent finding = direct support for C1/C2/C3
  over A1.

From **Koterba et al. (`llmsast`)**:
- Concrete target to beat/contextualize: Semgrep F1 0.66 on OWASP Benchmark v1.2.
- They report per-CWE precision/recall/F1 and a held-out external dataset — same
  structure we planned; good precedent for our held-out (Python Benchmark) design.
- Since they did LLM-vs-Semgrep substitution, our reportable contribution is the
  combination cells (triage, rule authoring) and the DAST axis.

---

## Update — A1 redefined as multi-agent roles

A1 is no longer "one model operates the scanners over multiple steps." It is now a
**fixed, small set of specialized agent roles working together**, e.g. a scanning agent
that drives Semgrep/ZAP plus a separate verifier agent that checks its findings before
they're reported (could extend to a triage agent, a remediation agent, etc.). This is
closer to how real agentic security tools are structured (PentestGPT decomposes into
cooperating modules; our own webllm citation's ablation shows distinct roles — response
interpretation, context prioritization, explanation — contribute differently). Implication
for the build: A1's harness needs to support role-to-role handoffs (agent A's output is
agent B's input), not just one agent with more tool calls. Still scoped as a demo on the
realistic apps, not a full Benchmark sweep, per the earlier decision.

---

## Build cleanup / tech debt (revisit before the report)

Running list of shortcuts taken in the `vulnbench` harness to keep moving; fine for now,
clean up before final.

1. **Semgrep executable resolution.** `scanners/semgrep_runner.py` resolves `semgrep` via
   PATH and *also* falls back to the directory next to `sys.executable` (the venv's `bin/`).
   The fallback exists only because the dev machine's system Python is PEP-668
   externally-managed, so Semgrep was `pip install`ed *into the project venv* rather than
   globally — and a subprocess's PATH doesn't include `.venv/bin`. Cleanup options: (a)
   standardize on a global install (`brew install semgrep` / `pipx install semgrep`) and
   drop the fallback, or (b) keep the fallback (most robust across the 5 teammates' setups).
   Harmless either way — the PATH lookup wins first when Semgrep is global. Decide as a team.
   First real B1 run used the venv install: F1 0.61 / recall 0.59 / FPR 0.39 on full
   BenchmarkJava v1.2 with `p/owasp-top-ten` (sanity-checks against the paper's Semgrep 0.66).

2. **Registry ruleset is fetched over the network (reproducibility risk).** B1/C1 default to
   the `p/owasp-top-ten` registry ruleset, which Semgrep pulls from semgrep.dev. It can
   change over time and needs connectivity, which weakens "fixed scanner versions" for scored
   runs. The scorecard now records the Semgrep version in `trace.semgrep_version`, but NOT the
   ruleset contents/hash. Decision for the team: (a) vendor a pinned local ruleset YAML and
   point `--config` at the file, or (b) keep the registry ruleset and additionally record its
   fetched version/hash. Pick before the scored sweep. (Left as-is for now, intentionally.)

---

## HANDOVER — state of the `vulnbench` build (for a fresh chat)

The harness lives in `code/` as a Python package `vulnbench`. Everything below is built,
tested, and runnable today.

**Environment.** Dev machine is macOS, system Python is PEP-668 externally-managed (no global
pip). Use the project venv: `code/.venv`. It has the package installed editable plus `semgrep`,
`rich`, `ruff`, `pytest`. Recreate with `python3 -m venv .venv && .venv/bin/pip install -e
'.[dev,pretty]'` then `.venv/bin/pip install semgrep`. Local tooling present: python3.14,
docker, java26. NOT installed: ollama (needed for real B3/C1/A1 LLM runs).

**What works.**
- Conditions: B1 (Semgrep), B3 (LLM-only), C1 (LLM+Semgrep triage) implemented; B2/C2/C3/A1
  are registered stubs (`conditions/stubs.py`) that raise NotImplementedError with their design.
- Scoring: OWASP Benchmark CSV auto-scoring (`scoring/benchmark.py`) + realistic-app fuzzy
  list-match (`scoring/listmatch.py`). Metrics: precision/recall/F1/FPR/Youden-J + tokens + latency.
- CLI: `python -m vulnbench.cli list|run`. `run` has a colorful/animated rich summary
  (`report.py`); `-o` writes the scorecard, `--findings-out` dumps raw findings, `--plain`
  forces plain, `--debug` re-raises, `--config '{...}'` passes knobs (max_files, max_file_bytes,
  semgrep_ruleset).
- Reliability: 46 pytest tests + ruff clean (config in pyproject; line-length 100, StrEnum).
- Real data: OWASP **BenchmarkJava is cloned at `code/targets/BenchmarkJava`** (gitignored,
  2740 test cases). Real scored B1 = **F1 0.61 / P 0.62 / R 0.59 / FPR 0.39** with `p/owasp-top-ten`.

**Key seams (don't re-derive).** `schema.Finding` (CWE + Location + verdict/evidence);
`models.ModelBackend.complete(messages, tools?)` with backends `local:` (Ollama, scored default
qwen3-coder:14b) / `api:anthropic:` (ceiling) / `mock` (offline, used by tests);
`conditions.Condition.run(target)->findings+usage`; `harness.run_one/run_matrix` emit RunRecord
with provenance.

**Next steps, in priority order.**
1. Install Ollama + `ollama pull qwen3-coder:14b`, then first real **C1** run on BenchmarkJava
   (the highest-value LLM cell) — compare F1 vs B1's 0.61.
2. Implement **B2/C2 (ZAP)**: deploy Benchmark as a running app (Docker), drive ZAP REST
   (spider→active scan→alerts), map alerts to ENDPOINT-location Findings.
3. Implement **C3** (LLM authors Semgrep rules offline, scored on held-out split).
4. Decide the two open tech-debt items above (Semgrep resolution, ruleset pinning).

**Bugs already fixed (don't reintroduce):** latency used to undercount combined conditions
(now total wall-clock + separate model_seconds); `Location.test_case` field collided with a
same-named classmethod factory (factory renamed `for_test_case`).

**GitHub:** pushed to a new repo on the user's account (`advaitsangle`), no Claude co-author
on commits (per user instruction — keep it that way for future commits).