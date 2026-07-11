package deps

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, fakeVulnSource{}, nil)

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
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, fakeVulnSource{}, nil)

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
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, vs, nil)

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
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, vs, nil)

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != finding.Info {
		t.Errorf("LOW-only vulns should map to INFO, got: %+v", findings)
	}
}

func TestScanAdapterErrorPropagates(t *testing.T) {
	s := NewWithSources(testCfg(), []adapter.Adapter{stubAdapter{err: errors.New("no lockfile")}}, fakeVulnSource{}, nil)
	if _, err := s.Scan(); err == nil {
		t.Fatal("Scan() error = nil, want adapter error")
	}
}

func TestScanVulnSourceErrorPropagates(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("x", "1.0.0", "MIT")}}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, fakeVulnSource{err: errors.New("osv down")}, nil)
	if _, err := s.Scan(); err == nil {
		t.Fatal("Scan() error = nil, want vuln source error")
	}
}

func TestScannerName(t *testing.T) {
	s := NewWithSources(testCfg(), nil, fakeVulnSource{}, nil)
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

func TestNewWiresPipAndCargoAdapters(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("version = 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.DepsConfig{Ecosystems: []string{"npm", "pip", "cargo"}}
	s := New(cfg, dir)
	if len(s.adapters) != 2 {
		t.Fatalf("adapters = %d, want 2 (pip + cargo; npm lockfile absent)", len(s.adapters))
	}
	names := map[string]bool{}
	for _, a := range s.adapters {
		names[a.Name()] = true
	}
	if !names["pip"] || !names["cargo"] {
		t.Errorf("adapter names = %v, want pip and cargo", names)
	}
}

type fakePublishSource struct {
	dates map[string]time.Time // key: ecosystem/name
	err   error
	calls int
}

func (f *fakePublishSource) LastPublish(pkg Package) (time.Time, error) {
	f.calls++
	if f.err != nil {
		return time.Time{}, f.err
	}
	return f.dates[pkg.Ecosystem+"/"+pkg.Name], nil
}

func TestScanStalePackageProducesInfoFinding(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("old-pkg", "1.0.0", "MIT")}}
	pub := &fakePublishSource{dates: map[string]time.Time{
		"npm/old-pkg": time.Now().AddDate(-2, 0, 0), // last release 2 years ago
	}}
	cfg := testCfg()
	cfg.StalenessDays = 365

	s := NewWithSources(cfg, []adapter.Adapter{a}, fakeVulnSource{}, pub)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	f := findByTitlePart(findings, "old-pkg")
	if f == nil {
		t.Fatalf("no staleness finding for old-pkg in %v", findings)
	}
	if f.Severity != finding.Info {
		t.Errorf("severity = %v, want INFO", f.Severity)
	}
	if !strings.Contains(f.Title, "no release") {
		t.Errorf("title = %q, want it to mention no release", f.Title)
	}
}

func TestScanFreshPackageNotFlaggedStale(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("fresh-pkg", "1.0.0", "MIT")}}
	pub := &fakePublishSource{dates: map[string]time.Time{
		"npm/fresh-pkg": time.Now().AddDate(0, -1, 0), // released last month
	}}
	cfg := testCfg()
	cfg.StalenessDays = 365

	s := NewWithSources(cfg, []adapter.Adapter{a}, fakeVulnSource{}, pub)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if f := findByTitlePart(findings, "no release"); f != nil {
		t.Errorf("fresh package flagged stale: %v", f)
	}
}

func TestScanStalenessDisabledSkipsLookups(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("pkg", "1.0.0", "MIT")}}
	pub := &fakePublishSource{}
	cfg := testCfg()
	cfg.StalenessDays = 0 // disabled

	s := NewWithSources(cfg, []adapter.Adapter{a}, fakeVulnSource{}, pub)
	if _, err := s.Scan(); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if pub.calls != 0 {
		t.Errorf("publish source called %d times with staleness disabled, want 0", pub.calls)
	}
}

func TestScanStalenessLookupErrorIsSkippedNotFatal(t *testing.T) {
	a := stubAdapter{records: []adapter.RawRecord{record("pkg", "1.0.0", "MIT")}}
	pub := &fakePublishSource{err: errors.New("registry down")}
	cfg := testCfg()
	cfg.StalenessDays = 365

	s := NewWithSources(cfg, []adapter.Adapter{a}, fakeVulnSource{}, pub)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v, staleness is best-effort and must not fail the scan", err)
	}
	if f := findByTitlePart(findings, "no release"); f != nil {
		t.Errorf("errored lookup produced a finding: %v", f)
	}
}

func TestScanStalenessDedupesByPackage(t *testing.T) {
	// same package appearing twice (e.g. two lockfile paths) → one lookup
	a := stubAdapter{records: []adapter.RawRecord{
		record("dup", "1.0.0", "MIT"),
		record("dup", "1.0.0", "MIT"),
	}}
	pub := &fakePublishSource{dates: map[string]time.Time{}}
	cfg := testCfg()
	cfg.StalenessDays = 365

	s := NewWithSources(cfg, []adapter.Adapter{a}, fakeVulnSource{}, pub)
	if _, err := s.Scan(); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if pub.calls != 1 {
		t.Errorf("publish source called %d times for one unique package, want 1", pub.calls)
	}
}
