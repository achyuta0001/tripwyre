package deps

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achyuta0001/tripwyre/internal/adapter"
	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
)

type stubAdapter struct {
	records []adapter.RawRecord
	err     error
}

func (s stubAdapter) Name() string                          { return "stub" }
func (s stubAdapter) Collect() ([]adapter.RawRecord, error) { return s.records, s.err }

type fakeVulnSource struct {
	vulns map[Package][]Vuln
	err   error
}

func (f fakeVulnSource) FindVulns(pkgs []Package) (map[Package][]Vuln, error) {
	return f.vulns, f.err
}

func record(name, version, license string) adapter.RawRecord {
	return adapter.RawRecord{
		Source: "package-lock.json",
		Type:   "npm-package",
		Payload: map[string]any{
			"ecosystem": "npm",
			"name":      name,
			"version":   version,
			"license":   license,
			"dev":       false,
		},
	}
}

func testCfg() config.DepsConfig {
	return config.DepsConfig{
		Ecosystems:       []string{"npm"},
		LicenseAllowlist: []string{"MIT", "Apache-2.0"},
	}
}

func findByTitlePart(findings []finding.Finding, part string) *finding.Finding {
	for i := range findings {
		if strings.Contains(findings[i].Title, part) {
			return &findings[i]
		}
	}
	return nil
}

func TestScanLicenseNotInAllowlist(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{
		record("good-pkg", "1.0.0", "MIT"),
		record("bad-pkg", "2.0.0", "GPL-3.0"),
	}}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, fakeVulnSource{})

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	f := findByTitlePart(findings, "bad-pkg")
	if f == nil {
		t.Fatalf("no finding for disallowed license, findings: %+v", findings)
	}
	if f.Severity != finding.Warning {
		t.Errorf("license finding severity = %v, want WARNING", f.Severity)
	}
	if !strings.Contains(f.Title, "GPL-3.0") {
		t.Errorf("title = %q, want it to name the license", f.Title)
	}
	if findByTitlePart(findings, "good-pkg") != nil {
		t.Error("allowlisted package must not produce a finding")
	}
}

func TestScanUnknownLicenseIsNotFlagged(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("no-license-pkg", "1.0.0", "")}}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, fakeVulnSource{})

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("empty license should not be flagged, got: %+v", findings)
	}
}

func TestScanCVEsProduceSeverityMappedFinding(t *testing.T) {
	lodash := Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	vs := fakeVulnSource{vulns: map[Package][]Vuln{
		lodash: {
			{ID: "GHSA-1", Severity: "HIGH", Summary: "ReDoS"},
			{ID: "GHSA-2", Severity: "MODERATE", Summary: "Command injection"},
		},
	}}
	a := stubAdapter{records: []adapter.RawRecord{record("lodash", "4.17.20", "MIT")}}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, vs)

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Severity != finding.Critical {
		t.Errorf("severity = %v, want CRITICAL (HIGH vuln present)", f.Severity)
	}
	if !strings.Contains(f.Title, "lodash 4.17.20") || !strings.Contains(f.Title, "2 CVEs") {
		t.Errorf("title = %q, want package, version and CVE count", f.Title)
	}
	if f.Scanner != finding.ScannerDeps {
		t.Errorf("scanner = %v, want deps", f.Scanner)
	}
	// vuln summaries must land in Context for future LLM synthesis
	if !strings.Contains(f.Context, "ReDoS") {
		t.Errorf("Context = %q, want vuln summaries", f.Context)
	}
}

func TestScanLowSeverityOnlyIsInfo(t *testing.T) {
	pkg := Package{Ecosystem: "npm", Name: "meh", Version: "1.0.0"}
	vs := fakeVulnSource{vulns: map[Package][]Vuln{
		pkg: {{ID: "GHSA-3", Severity: "LOW"}},
	}}
	a := stubAdapter{records: []adapter.RawRecord{record("meh", "1.0.0", "MIT")}}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, vs)

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != finding.Info {
		t.Errorf("LOW-only vulns should map to INFO, got: %+v", findings)
	}
}

func TestScanAdapterErrorPropagates(t *testing.T) {
	s := NewWithSources(testCfg(), []adapter.Adapter{stubAdapter{err: errors.New("no lockfile")}}, fakeVulnSource{})
	if _, err := s.Scan(); err == nil {
		t.Fatal("Scan() error = nil, want adapter error")
	}
}

func TestScanVulnSourceErrorPropagates(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("x", "1.0.0", "MIT")}}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, fakeVulnSource{err: errors.New("osv down")})
	if _, err := s.Scan(); err == nil {
		t.Fatal("Scan() error = nil, want vuln source error")
	}
}

func TestScannerName(t *testing.T) {
	s := NewWithSources(testCfg(), nil, fakeVulnSource{})
	if s.Name() != "deps" {
		t.Errorf("Name() = %q, want deps", s.Name())
	}
}

func TestNewSkipsMissingLockfiles(t *testing.T) {
	dir := t.TempDir()

	s := New(testCfg(), dir)
	if len(s.adapters) != 0 {
		t.Errorf("no lockfile present: adapters = %d, want 0", len(s.adapters))
	}

	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s = New(testCfg(), dir)
	if len(s.adapters) != 1 {
		t.Errorf("lockfile present: adapters = %d, want 1", len(s.adapters))
	}
	if s.vulns == nil {
		t.Error("New must wire a vuln source")
	}
}
