# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

tripwyre is a CLI that scans a project for three kinds of risk — dependency CVEs/license/staleness, config drift, and log anomalies — and emits a single prioritized report. No cloud, no LLM required by default; LLM synthesis is an opt-in paid upgrade for cross-scanner correlation.

This is a **proprietary commercial product**, not open source (see LICENSE). New dependencies must have permissive licenses (MIT, Apache-2.0, BSD, ISC) and be added to THIRD_PARTY_LICENSES.md; copyleft (GPL/AGPL/LGPL) is incompatible with the closed-source binary.

All three scanners are implemented with tests: deps (npm/pip/cargo + OSV.dev + registry staleness), config drift (.env/TOML/YAML diffing), and logs (plaintext + JSON-lines, spike detection + clustering), plus the shared scan pipeline and a composite GitHub Action (see Build Sequence below for what remains).

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

- **`internal/adapter`** — `Adapter` interface (`Name() string`, `Collect() ([]RawRecord, error)`). Each source implements this to produce source-agnostic `RawRecord`s. Implemented: `npm` (package-lock.json v2/v3 `packages` format with v1 `dependencies` fallback; name/version/license/dev), `pip` (requirements.txt; only exact `==` pins are emitted — ranges can't map to one OSV version; extras/markers/comments stripped), `cargo` (Cargo.lock `[[package]]`; entries without `source` are the workspace's own crates and skipped), `dotenv` (.env), `structured` (.toml/.yaml/.yml flattened to dotted keys, `FlattenFile` exported), `logfile` (plaintext logs), `jsonlog` (JSON lines; timestamp/level/message extracted from common field-name variants incl. epoch-seconds `ts`; non-JSON lines skipped). OSV ecosystem strings are exact: `npm`, `PyPI`, `crates.io`.
- **`internal/scanner/configscan`** — config drift scanner. Diffs each source against the expected state from `cfg.Expected`; sources and the expected file both pick their parser by extension (.toml/.yaml/.yml → `internal/adapter/structured`, flattened to dotted string keys like `cache.ttl`; anything else → `internal/adapter/dotenv`, whose `ParseFile` is exported for reuse). Rules: key missing from source → WARNING, value drift → WARNING, key present but not expected → INFO. Values of keys matching `redact_patterns` are replaced with `[REDACTED]` before they reach any Finding — never let secret values into titles or details. Empty `cfg.Expected` disables the scanner; configured-but-missing expected file errors at `New` (silently skipping would hide all drift).
- **`internal/scanner/logscan`** — log anomaly scanner; sources pick their adapter by extension (.json/.jsonl → `internal/adapter/jsonlog`, else `internal/adapter/logfile`: plaintext lines, best-effort ISO-8601 timestamp + level extraction). Spike rule: ≥ `error_spike_threshold` ERROR/FATAL lines from one source in a fixed 15-minute window → WARNING. Cluster rule: messages normalized (digits/hex → `#`, lowercased) and grouped; ≥ `cluster_min_size` occurrences → INFO. Lines without timestamps can still cluster but can't spike.
- **GitHub Action** — `action.yml` (composite, repo root) builds the binary, runs `scan --format=json`, upserts a PR comment (marker `<!-- tripwyre-report -->`) via `scripts/render-comment.sh` (jq; test it locally by piping a JSON report in), then enforces the scan exit code.
- **`internal/scanner/deps`** — the first real scanner. Rules: CVE lookup via the `VulnSource` interface (production impl is `OSVClient` in `osv.go`: one `/v1/querybatch` call per 1000 packages, then one `/v1/vulns/{id}` fetch per unique vuln ID) and license-allowlist check (unknown/empty licenses are deliberately not flagged — too noisy). Severity mapping: any CRITICAL/HIGH vuln → CRITICAL finding, MODERATE/unknown → WARNING, LOW-only → INFO. `New(cfg, dir)` skips ecosystems whose lockfile is absent from dir so `scan` works in any project; `NewWithSources` injects fake adapters/vuln/publish sources in tests. Staleness rule: `PublishSource` interface (production impl `RegistryClient` in `registry.go`, hitting registry.npmjs.org / pypi.org / crates.io — crates.io requires a User-Agent header) flags packages with no release in `staleness_days` as INFO. It is opt-in (`staleness_days` defaults to 0 = disabled) because it costs one GET per unique package, and best-effort: a failed lookup skips the package instead of failing the scan.
- **`internal/finding`** — the canonical `Finding` struct that every scanner must emit. This is the contract point of the whole system: everything upstream (adapters, rules) is scanner-specific and swappable; everything downstream (reporters, CI integration) is generic and depends only on `Finding`.
- **`internal/scanner`** — `Scanner` interface (`Name() string`, `Scan() ([]finding.Finding, error)`) that each domain scanner (deps/config/logs) implements, wrapping its adapters + rules.
- **`internal/reporter`** — `Synthesizer` interface (`Summarize(findings []finding.Finding) (string, error)`). Three implementations, resolved in `selectReporter` in `cmd/run.go`: `TemplateReporter` (grouped-by-severity plaintext, default), `JSONReporter` (`{summary, findings}`; `findings` always `[]`, never `null`), and `LLMReporter` (`llm.go`, enabled via `[reporter] backend = "llm"` in tripwyre.toml). Precedence: `--format=json` always wins over the LLM backend so machine-readable output stays deterministic. `LLMReporter` uses the official anthropic-sdk-go, defaults to `claude-opus-4-8` and env `ANTHROPIC_API_KEY` (a missing key errors at construction), always prints the deterministic template report before the synthesis, omits the `thinking` param so any user-configured model works, and must only ever receive processed `Finding`s (titles/Detail/Context) — never raw logs or config — to keep token cost bounded. Tests fake the Messages API with httptest via `option.WithBaseURL`.
- **`cmd/`** — Cobra commands (`scan`, `deps`, `config`, `logs`). All four delegate to `runScan` in `cmd/run.go`, the shared pipeline: load config → run scanners → report → `checkFailOn`. Each subcommand only supplies a `func(*config.Config) []scanner.Scanner` builder (currently returning nil with TODOs). To wire in a real scanner, return it from the builder in the relevant command file — do not add a new call path.
- **`internal/config`** — `config.Load(path)` reads `tripwyre.toml` via BurntSushi/toml, returning sane defaults if the file doesn't exist (see `tripwyre.toml.example` for the schema: `[deps]`, `[config]`, `[logs]`, `[reporter]` sections).

### `--fail-on` semantics

`checkFailOn` (in `cmd/scan.go`) returns an error if any finding's severity is at or above the given threshold (`critical` > `warning` > `info`, case-insensitive); `Execute()` turns that into exit code 1. Never call `os.Exit` inside command logic — return errors so the pipeline stays testable. This is what makes `tripwyre scan --fail-on=critical` usable as a CI gate.

## Build Sequence (current state)

From the README — treat this as the source of truth for what's implemented vs. stubbed:

- [x] Canonical `Finding` type + `TemplateReporter`
- [x] CLI skeleton (`scan`, `deps`, `config`, `logs`, `--fail-on`)
- [x] `--fail-on` CI exit code integration (tested)
- [x] Deps scanner — npm/pip/cargo adapters + OSV.dev CVE lookup + license rules
- [x] Config scanner — `.env`/TOML/YAML adapters + diff rules (secrets redacted)
- [x] Log scanner — plaintext + JSON-lines adapters + spike detection + clustering
- [x] GitHub Action (`action.yml` + `scripts/render-comment.sh`) with PR findings comment
- [x] Deps staleness rule (npm/PyPI/crates.io publish dates; opt-in via `staleness_days > 0`)
- [x] `LLMReporter` + cross-scanner synthesis
- [ ] Remote adapters (k8s API, Loki, Elasticsearch — need live infra)
- [ ] More lockfiles (poetry.lock, go.sum)

When implementing a scanner, wire it into the corresponding `cmd/*.go` file by uncommenting/replacing the TODO block, not by adding a new call path.
