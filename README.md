# tripwyre

A unified project intelligence CLI. Scans dependencies, config, and logs — surfaces findings in one prioritized report.

No cloud required. No LLM required. Optional LLM synthesis when you want it.

---

## The Problem

Modern projects have three blind spots:

1. **Dependencies** — you added a package six months ago and haven't checked it since. CVEs accumulate silently.
2. **Config** — prod drifted from what's in version control. No one noticed until something broke.
3. **Logs** — errors are happening but buried in noise. You only look when something pages you.

Three separate tools exist for each. None of them talk to each other.

---

## What tripwyre does

```
tripwyre scan          # runs all three scanners
tripwyre deps          # dependency risk only
tripwyre config        # config drift only
tripwyre logs          # log patterns only

tripwyre scan --format=json   # machine-readable output for jq, CI annotations, dashboards
```

Single prioritized output:

```
CRITICAL  [deps]    lodash 4.17.20 — 3 CVEs (2 high, 1 medium)
WARNING   [config]  DB_POOL_SIZE drifted in prod (expected: 10, observed: 3)
WARNING   [deps]    react-scripts license is UNLICENSED
INFO      [logs]    error spike in auth-service — 47 errors between 03:00–03:15 UTC
INFO      [config]  CACHE_TTL missing in staging, present in prod
```

---

## Architecture

```
Source Adapters → Canonical Layer → Rules Engine → Finding → Report Layer
                                                                   ↑
                                                        Synthesizer interface
                                                        ├── TemplateReporter  (free, default)
                                                        └── LLMReporter       (opt-in, paid)
```

### Canonical Finding

Every scanner emits the same structure:

```go
type Finding struct {
    Severity  Severity       // CRITICAL | WARNING | INFO
    Scanner   Scanner        // deps | config | logs
    Title     string
    Detail    map[string]any // structured, renderer by TemplateReporter
    Context   string         // raw excerpt passed to LLMReporter if enabled
    Timestamp time.Time
}
```

### Source Adapters

Each adapter implements:

```go
type Adapter interface {
    Name()    string
    Collect() ([]RawRecord, error)
}
```

**Deps adapters:** `npm` (package-lock.json), `pip` (requirements.txt / poetry.lock), `cargo` (Cargo.lock), `go` (go.sum)

**Config adapters:** `.env` files, TOML/YAML config, terraform `.tfvars`

**Log adapters:** plaintext log files, JSON structured logs, Kubernetes API, Loki, Elasticsearch

### Rules Engine

Rules are pure functions: `RawRecord → *Finding`. No LLM cost, no network calls beyond OSV.dev.

**Deps rules:**
- CVE lookup against [OSV.dev](https://osv.dev) (free, no auth)
- License compatibility check against allowlist
- Staleness flag (no publish in N days)

**Config rules:**
- Key present in expected, missing in observed → `WARNING`
- Value mismatch → `WARNING` (redacts secrets before output)
- Type mismatch → `WARNING`

**Log rules:**
- Error rate spike (rolling window, configurable threshold)
- Recurring error clustering (edit-distance grouping)
- Slow request detection (parse duration fields)

### Synthesizer Interface

```go
type Synthesizer interface {
    Summarize(findings []finding.Finding) (string, error)
}
```

`TemplateReporter` renders structured markdown from finding fields — free, default, no dependencies.

`LLMReporter` (coming soon) sends the structured finding list to your LLM of choice. The LLM never receives raw logs or raw config — only processed findings. Token counts stay low; cost stays predictable.

---

## The Cross-Scanner Advantage

When LLM synthesis is enabled, findings from all three scanners are sent together. This enables correlations no single tool surfaces:

> "Your DB_POOL_SIZE config drifted to 3 at the same time the auth-service error spike started at 03:00 UTC. The two are likely related."

Without LLM, you still see both findings — you just connect the dots yourself.

---

## Cost

| Component       | Cost                                    |
|-----------------|-----------------------------------------|
| Dep scanning    | $0 — OSV.dev API is free, no auth       |
| Config diffing  | $0 — local only                         |
| Log processing  | $0 — local or your existing infra       |
| LLM synthesis   | your API key, your model, your bill     |
| Hosting         | $0 — runs locally or in CI             |

---

## CI Integration

```yaml
- name: tripwyre scan
  run: tripwyre scan --fail-on=critical
```

Exits non-zero on any `CRITICAL` finding. Works with any CI that reads exit codes.

---

## Kubernetes

| Scanner | Where it runs        | How                                      |
|---------|----------------------|------------------------------------------|
| deps    | CI pipeline          | step on every PR                         |
| config  | in-cluster CronJob   | reads k8s API + git values               |
| logs    | in-cluster CronJob   | reads from k8s API or Loki/Elastic       |

---

## Configuration

```toml
# tripwyre.toml

[deps]
ecosystems = ["npm", "pip"]
license_allowlist = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
staleness_days = 365

[config]
sources = [".env", "config/prod.toml"]
expected = "config/expected.toml"
redact_patterns = [".*SECRET.*", ".*KEY.*", ".*PASSWORD.*"]

[logs]
sources = ["logs/app.log"]
error_spike_threshold = 20
cluster_min_size = 5

[reporter]
backend = "template"          # free default
# backend     = "llm"
# model       = "claude-haiku-4-5-20251001"
# api_key_env = "ANTHROPIC_API_KEY"
```

---

## Build Sequence

- [x] Canonical `Finding` type + `TemplateReporter`
- [x] CLI skeleton (`scan`, `deps`, `config`, `logs`, `--fail-on`)
- [x] `--fail-on` CI exit code integration
- [x] Deps scanner — npm adapter + OSV.dev CVE lookup + license rules
- [x] JSON output (`--format=json`)
- [x] Config scanner — `.env` adapter + diff rules (secrets redacted)
- [ ] Deps staleness rule (needs registry publish dates)
- [ ] Log scanner — plaintext adapter + spike detection + clustering
- [ ] Additional adapters (pip, cargo, YAML, JSON logs, k8s API)
- [ ] `LLMReporter` + cross-scanner synthesis

---

## Core Design Principle

> Everything above the canonical `Finding` is scanner-specific and swappable. Everything below it — the report format, the Synthesizer interface, the CI integration — never changes when a new scanner or adapter is added.

Rules handle the deterministic 90%. LLM handles the last 10%. You pay for neither until you choose to.

---

## License

tripwyre is proprietary software — see [LICENSE](LICENSE). It is not open source; use requires a commercial license agreement with the copyright holder. Bundled open-source components and their licenses are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
