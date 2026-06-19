# deploy — running the DAST stack (B2 / C2)

The dynamic conditions need *two* things up at once: the **application under test**
and an **OWASP ZAP daemon** to attack it. `docker-compose.yml` brings up both on
one network so the harness (running on your host) can drive ZAP, and ZAP can reach
the app by name.

```
host                        docker network
┌───────────────┐           ┌──────────────────────────────┐
│ vulnbench CLI │──:8090──▶ │ zap (daemon, REST API)        │
└───────────────┘           │      │ attacks                │
                            │      ▼                        │
                            │ benchmark (Tomcat https:8443) │
                            └──────────────────────────────┘
```

## Prerequisites

- Docker (Compose v2: `docker compose ...`).
- The OWASP Benchmark source cloned at `../targets/BenchmarkJava` (gitignored).
  Clone it once with:
  `git clone https://github.com/OWASP-Benchmark/BenchmarkJava targets/BenchmarkJava`.

## Bring it up

From `code/`:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

The **first** launch is slow: Maven downloads the dependency world and builds the
WAR (cached in the `maven-repo` volume, so later launches are quick). Wait until
the `benchmark` service is healthy (Compose reports it; or `curl -k
https://localhost:8443/benchmark/` once you publish 8443, but by default only ZAP's
port is exposed to the host).

## Run B2 against it

In another shell, from `code/`:

```bash
.venv/bin/python -m vulnbench.cli run --condition B2 \
    --url https://benchmark:8443/benchmark/ --kind benchmark \
    --ground-truth ./targets/BenchmarkJava/expectedresults-1.2.csv \
    --config '{"zap_url": "http://127.0.0.1:8090",
               "zap_seed_crawler": "targets/BenchmarkJava/data/benchmark-crawler-http.xml"}' \
    -o scorecard-b2.json --findings-out findings-b2.json
```

`zap_seed_crawler` is what makes the score meaningful — it seeds ZAP with each
test case's real request before scanning (see "Seeding vs spider" below). Add
`"zap_seed_limit": 40` for a quick partial run. The full ~2740-case active scan
is a multi-hour job.

Two URLs, intentionally different:

- `--url https://benchmark:8443/benchmark/` is the **scan target**, resolved
  **inside** the Docker network by ZAP (service name `benchmark`).
- `zap_url: http://127.0.0.1:8090` is where the **harness** reaches ZAP, via the
  published port on the host.

A full active scan of all 2740 Benchmark cases takes a while; raise the per-phase
ceiling with `--config '{..., "zap_max_wait": 7200}'` if a phase times out.

## Tear down

```bash
docker compose -f deploy/docker-compose.yml down            # keep the maven cache
docker compose -f deploy/docker-compose.yml down -v         # also drop the cache
```

## Notes / knobs

- **API key:** the daemon runs with `api.disablekey=true` for convenience. To
  require a key, set it in the compose `command` and pass
  `--config '{"zap_api_key": "<key>", ...}'`.
- **Self-signed cert:** the Benchmark serves HTTPS with a `changeit` keystore; ZAP
  accepts it by default, so no extra config is needed.
- **Disabled scanners / DOM-XSS:** B2 defaults to
  `zap_disable_scanners: ["40026"]`, turning off the browser-based DOM-XSS rule.
  It's irrelevant to the server-side Benchmark (nothing to detect) and its
  headless browser OOM-kills ZAP on a ~8 GB Docker VM. **For the realistic apps
  (Juice Shop, WebGoat, DVWA), which *do* have client-side/DOM-XSS bugs, re-enable
  it** with `--config '{"zap_disable_scanners": [], ...}'` and give Docker more RAM.
- **Memory:** the Benchmark Tomcat heap is capped at `-Xmx2g` in the compose (the
  pom default is 8 GB, larger than the whole Docker VM). Raise it if you also raise
  the VM's memory.
- **Seeding vs spider:** for fair Benchmark scores B2 must be run with
  `zap_seed_crawler` pointed at `targets/BenchmarkJava/data/benchmark-crawler-http.xml`
  (it replays each test case's real request so ZAP can attack inputs a blind spider
  never finds). Add `zap_seed_limit` for a quick partial scan.
- **Scoring:** ZAP alerts land as `ENDPOINT` findings whose URL carries the
  `BenchmarkTestNNNNN` id, so they auto-score against `expectedresults-1.2.csv`
  through the same path as Semgrep — no separate scorecard step.
