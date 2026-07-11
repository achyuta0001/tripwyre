// Package deps scans project dependencies for known CVEs and license
// policy violations. Records come from source adapters (npm, ...); CVE
// data comes from a VulnSource (OSV.dev in production).
package deps

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/achyuta0001/tripwyre/internal/adapter"
	"github.com/achyuta0001/tripwyre/internal/adapter/cargo"
	"github.com/achyuta0001/tripwyre/internal/adapter/npm"
	"github.com/achyuta0001/tripwyre/internal/adapter/pip"
	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
)

// Package identifies a dependency in a vulnerability database query.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

// Vuln is a single known vulnerability affecting a package.
type Vuln struct {
	ID       string
	Summary  string
	Severity string // CRITICAL | HIGH | MODERATE | LOW | "" (unknown)
}

// VulnSource answers "which of these packages have known vulns?".
// The production implementation queries OSV.dev.
type VulnSource interface {
	FindVulns(pkgs []Package) (map[Package][]Vuln, error)
}

// PublishSource answers "when was this package last published?".
// The production implementation queries the package registries
// (npm, PyPI, crates.io). A zero time means "unknown".
type PublishSource interface {
	LastPublish(pkg Package) (time.Time, error)
}

type Scanner struct {
	cfg       config.DepsConfig
	adapters  []adapter.Adapter
	vulns     VulnSource
	publishes PublishSource
}

// New builds the production scanner for a project directory: one adapter
// per configured ecosystem whose lockfile exists in dir, plus the live
// OSV.dev client. Missing lockfiles are skipped, not errors, so `scan`
// works in projects that don't use every configured ecosystem.
func New(cfg config.DepsConfig, dir string) *Scanner {
	var adapters []adapter.Adapter
	for _, eco := range cfg.Ecosystems {
		switch eco {
		case "npm":
			lock := filepath.Join(dir, "package-lock.json")
			if _, err := os.Stat(lock); err == nil {
				adapters = append(adapters, npm.New(lock))
			}
		case "pip":
			reqs := filepath.Join(dir, "requirements.txt")
			if _, err := os.Stat(reqs); err == nil {
				adapters = append(adapters, pip.New(reqs))
			}
		case "cargo":
			lock := filepath.Join(dir, "Cargo.lock")
			if _, err := os.Stat(lock); err == nil {
				adapters = append(adapters, cargo.New(lock))
			}
			// TODO: go (go.sum), pip poetry.lock
		}
	}
	return NewWithSources(cfg, adapters, NewOSVClient(""), NewRegistryClient())
}

// NewWithSources wires explicit adapters and data sources; used by tests.
func NewWithSources(cfg config.DepsConfig, adapters []adapter.Adapter, vulns VulnSource, publishes PublishSource) *Scanner {
	return &Scanner{cfg: cfg, adapters: adapters, vulns: vulns, publishes: publishes}
}

func (s *Scanner) Name() string { return "deps" }

func (s *Scanner) Scan() ([]finding.Finding, error) {
	var records []adapter.RawRecord
	for _, a := range s.adapters {
		recs, err := a.Collect()
		if err != nil {
			return nil, fmt.Errorf("%s adapter: %w", a.Name(), err)
		}
		records = append(records, recs...)
	}

	var findings []finding.Finding

	findings = append(findings, s.licenseFindings(records)...)

	cveFindings, err := s.cveFindings(records)
	if err != nil {
		return nil, err
	}
	findings = append(findings, cveFindings...)
	findings = append(findings, s.stalenessFindings(records)...)

	return findings, nil
}

// stalenessFindings flags packages whose registry hasn't seen a release
// in cfg.StalenessDays. Opt-in (staleness_days > 0): it costs one
// registry request per unique package. Best-effort: a failed or unknown
// lookup skips the package rather than failing the scan — staleness is
// an INFO heuristic, not worth breaking a CI gate over a flaky registry.
func (s *Scanner) stalenessFindings(records []adapter.RawRecord) []finding.Finding {
	if s.cfg.StalenessDays <= 0 || s.publishes == nil {
		return nil
	}

	seen := map[Package]bool{}
	var findings []finding.Finding
	for _, r := range records {
		eco, _ := r.Payload["ecosystem"].(string)
		name, _ := r.Payload["name"].(string)
		if name == "" {
			continue
		}
		pkg := Package{Ecosystem: eco, Name: name}
		if seen[pkg] {
			continue
		}
		seen[pkg] = true

		last, err := s.publishes.LastPublish(pkg)
		if err != nil || last.IsZero() {
			continue
		}
		age := int(time.Since(last).Hours() / 24)
		if age <= s.cfg.StalenessDays {
			continue
		}

		findings = append(findings, finding.Finding{
			Severity: finding.Info,
			Scanner:  finding.ScannerDeps,
			Title: fmt.Sprintf("%s — no release in %d days (last publish %s)",
				name, age, last.Format("2006-01-02")),
			Detail: map[string]any{
				"package":        name,
				"ecosystem":      eco,
				"last_publish":   last.Format("2006-01-02"),
				"age_days":       age,
				"threshold_days": s.cfg.StalenessDays,
			},
			Timestamp: time.Now(),
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	return findings
}

func (s *Scanner) licenseFindings(records []adapter.RawRecord) []finding.Finding {
	if len(s.cfg.LicenseAllowlist) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(s.cfg.LicenseAllowlist))
	for _, l := range s.cfg.LicenseAllowlist {
		allowed[l] = true
	}

	var findings []finding.Finding
	for _, r := range records {
		name, _ := r.Payload["name"].(string)
		version, _ := r.Payload["version"].(string)
		license, _ := r.Payload["license"].(string)

		// Unknown license is common in lockfiles (older npm versions omit
		// it); flagging every one would be noise, so skip empty.
		if license == "" || allowed[license] {
			continue
		}

		findings = append(findings, finding.Finding{
			Severity: finding.Warning,
			Scanner:  finding.ScannerDeps,
			Title:    fmt.Sprintf("%s %s license %s is not in allowlist", name, version, license),
			Detail: map[string]any{
				"package": name,
				"version": version,
				"license": license,
				"source":  r.Source,
			},
			Timestamp: time.Now(),
		})
	}
	return findings
}

func (s *Scanner) cveFindings(records []adapter.RawRecord) ([]finding.Finding, error) {
	var pkgs []Package
	for _, r := range records {
		eco, _ := r.Payload["ecosystem"].(string)
		name, _ := r.Payload["name"].(string)
		version, _ := r.Payload["version"].(string)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, Package{Ecosystem: eco, Name: name, Version: version})
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	vulnsByPkg, err := s.vulns.FindVulns(pkgs)
	if err != nil {
		return nil, fmt.Errorf("vulnerability lookup: %w", err)
	}

	var findings []finding.Finding
	for pkg, vulns := range vulnsByPkg {
		if len(vulns) == 0 {
			continue
		}
		findings = append(findings, cveFinding(pkg, vulns))
	}

	// map iteration order is random; keep report output stable
	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })

	return findings, nil
}

func cveFinding(pkg Package, vulns []Vuln) finding.Finding {
	counts := map[string]int{}
	ids := make([]string, 0, len(vulns))
	var summaries []string
	for _, v := range vulns {
		sev := v.Severity
		if sev == "" {
			sev = "UNKNOWN"
		}
		counts[strings.ToUpper(sev)]++
		ids = append(ids, v.ID)
		if v.Summary != "" {
			summaries = append(summaries, fmt.Sprintf("%s: %s", v.ID, v.Summary))
		}
	}

	severity := finding.Info
	switch {
	case counts["CRITICAL"] > 0 || counts["HIGH"] > 0:
		severity = finding.Critical
	case counts["MODERATE"] > 0 || counts["UNKNOWN"] > 0:
		severity = finding.Warning
	}

	var parts []string
	for _, level := range []string{"CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"} {
		if counts[level] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[level], strings.ToLower(level)))
		}
	}

	return finding.Finding{
		Severity: severity,
		Scanner:  finding.ScannerDeps,
		Title: fmt.Sprintf("%s %s — %d CVEs (%s)",
			pkg.Name, pkg.Version, len(vulns), strings.Join(parts, ", ")),
		Detail: map[string]any{
			"package":   pkg.Name,
			"version":   pkg.Version,
			"ecosystem": pkg.Ecosystem,
			"vuln_ids":  ids,
		},
		Context:   strings.Join(summaries, "\n"),
		Timestamp: time.Now(),
	}
}
