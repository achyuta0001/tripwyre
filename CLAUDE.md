# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

tripwyre is a CLI that scans a project for three kinds of risk — dependency CVEs/license/staleness, config drift, and log anomalies — and emits a single prioritized report. No cloud, no LLM required by default; LLM synthesis is an opt-in paid upgrade for cross-scanner correlation.

This is a **proprietary commercial product**, not open source (see LICENSE). New dependencies must have permissive licenses (MIT, Apache-2.0, BSD, ISC) and be added to THIRD_PARTY_LICENSES.md; copyleft (GPL/AGPL/LGPL) is incompatible with the closed-source binary.

The CLI skeleton, canonical `Finding` type, core interfaces, shared scan pipeline, and the deps scanner (npm + OSV.dev) are implemented with tests; the config and log scanners are still stubs (see Build Sequence below).

## Commands

```
go build ./...           # build everything
go test ./...            # run all tests
go test ./cmd/ -run TestCheckFailOn   # run a single test
gofmt -l .               # list unformatted files (CI fails on any)
go vet ./...             # static checks (CI enforces)
go run . scan            # run the CLI locally, e.g. `go run . scan --config tripwyre.toml`
```

CI (`.github/workflows/build.yml`) runs gofmt check, `go vet`, `go build`, and `go test` on push/PR to `main`.

Release builds stamp the version via ldflags:

```
go build -ldflags "-X github.com/achyuta0001/tripwyre/cmd.version=v1.2.3" .
```

## Architecture

Data flows in one direction through four layers, and code should be added respecting that direction:

```
Source Adapters → Canonical Layer → Rules Engine → Finding → Report Layer
                                                                   ↑
                                                        Synthesizer interface
                                                        ├── TemplateReporter  (free, default)
                                                        └── LLMReporter       (opt-in, paid)
```

- **`internal/adapter`** — `Adapter` interface (`Name() string`, `Collect() ([]RawRecord, error)`). Each source (npm/pip/cargo/go for deps; .env/TOML/YAML/tfvars for config; plaintext/JSON/k8s/Loki/Elasticsearch for logs) implements this to produce source-agnostic `RawRecord`s. `internal/adapter/npm` parses package-lock.json (v2/v3 `packages` format with v1 `dependencies` fallback) into records carrying name/version/license/dev.
- **`internal/scanner/deps`** — the first real scanner. Rules: CVE lookup via the `VulnSource` interface (production impl is `OSVClient` in `osv.go`: one `/v1/querybatch` call per 1000 packages, then one `/v1/vulns/{id}` fetch per unique vuln ID) and license-allowlist check (unknown/empty licenses are deliberately not flagged — too noisy). Severity mapping: any CRITICAL/HIGH vuln → CRITICAL finding, MODERATE/unknown → WARNING, LOW-only → INFO. `New(cfg, dir)` skips ecosystems whose lockfile is absent from dir so `scan` works in any project; `NewWithSources` injects fake adapters/vuln sources in tests. Staleness rule is a TODO (needs registry publish dates).
- **`internal/finding`** — the canonical `Finding` struct that every scanner must emit. This is the contract point of the whole system: everything upstream (adapters, rules) is scanner-specific and swappable; everything downstream (reporters, CI integration) is generic and depends only on `Finding`.
- **`internal/scanner`** — `Scanner` interface (`Name() string`, `Scan() ([]finding.Finding, error)`) that each domain scanner (deps/config/logs) implements, wrapping its adapters + rules.
- **`internal/reporter`** — `Synthesizer` interface (`Summarize(findings []finding.Finding) (string, error)`). `TemplateReporter` renders grouped-by-severity plaintext (default); `JSONReporter` emits `{summary, findings}` JSON (selected via the global `--format=json` flag, resolved in `selectReporter` in `cmd/run.go`; `findings` is always `[]`, never `null`). An `LLMReporter` is planned but not yet built; when added it must only ever receive processed `Finding`s (via the `Context` field), never raw logs/config, to keep token cost bounded.
- **`cmd/`** — Cobra commands (`scan`, `deps`, `config`, `logs`). All four delegate to `runScan` in `cmd/run.go`, the shared pipeline: load config → run scanners → report → `checkFailOn`. Each subcommand only supplies a `func(*config.Config) []scanner.Scanner` builder (currently returning nil with TODOs). To wire in a real scanner, return it from the builder in the relevant command file — do not add a new call path.
- **`internal/config`** — `config.Load(path)` reads `tripwyre.toml` via BurntSushi/toml, returning sane defaults if the file doesn't exist (see `tripwyre.toml.example` for the schema: `[deps]`, `[config]`, `[logs]`, `[reporter]` sections).

### `--fail-on` semantics

`checkFailOn` (in `cmd/scan.go`) returns an error if any finding's severity is at or above the given threshold (`critical` > `warning` > `info`, case-insensitive); `Execute()` turns that into exit code 1. Never call `os.Exit` inside command logic — return errors so the pipeline stays testable. This is what makes `tripwyre scan --fail-on=critical` usable as a CI gate.

## Build Sequence (current state)

From the README — treat this as the source of truth for what's implemented vs. stubbed:

- [x] Canonical `Finding` type + `TemplateReporter`
- [x] CLI skeleton (`scan`, `deps`, `config`, `logs`, `--fail-on`)
- [x] `--fail-on` CI exit code integration (tested)
- [x] Deps scanner — npm adapter + OSV.dev CVE lookup + license rules
- [ ] Deps staleness rule (needs registry publish dates)
- [ ] Config scanner — `.env` adapter + diff rules
- [ ] Log scanner — plaintext adapter + spike detection + clustering
- [ ] Additional adapters (pip, cargo, YAML, JSON logs, k8s API)
- [ ] `LLMReporter` + cross-scanner synthesis

When implementing a scanner, wire it into the corresponding `cmd/*.go` file by uncommenting/replacing the TODO block, not by adding a new call path.
