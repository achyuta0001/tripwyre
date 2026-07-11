package configscan

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
	source string
	kv     map[string]string
	err    error
}

func (s stubAdapter) Name() string { return "stub" }
func (s stubAdapter) Collect() ([]adapter.RawRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	var records []adapter.RawRecord
	for k, v := range s.kv {
		records = append(records, adapter.RawRecord{
			Source:  s.source,
			Type:    "config-kv",
			Payload: map[string]any{"key": k, "value": v},
		})
	}
	return records, nil
}

func testCfg() config.ConfigConfig {
	return config.ConfigConfig{
		RedactPatterns: []string{".*SECRET.*", ".*PASSWORD.*"},
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

func scanWith(t *testing.T, observed map[string]string, expected map[string]string) []finding.Finding {
	t.Helper()
	a := stubAdapter{source: ".env", kv: observed}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, expected)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return findings
}

func TestScanNoDriftNoFindings(t *testing.T) {
	kv := map[string]string{"DB_HOST": "localhost", "DB_POOL_SIZE": "10"}
	if findings := scanWith(t, kv, kv); len(findings) != 0 {
		t.Errorf("identical config should yield no findings, got: %+v", findings)
	}
}

func TestScanMissingKeyIsWarning(t *testing.T) {
	findings := scanWith(t,
		map[string]string{"DB_HOST": "localhost"},
		map[string]string{"DB_HOST": "localhost", "CACHE_TTL": "60"},
	)

	f := findByTitlePart(findings, "CACHE_TTL")
	if f == nil {
		t.Fatalf("no finding for missing key, findings: %+v", findings)
	}
	if f.Severity != finding.Warning {
		t.Errorf("severity = %v, want WARNING", f.Severity)
	}
	if !strings.Contains(f.Title, "missing") {
		t.Errorf("title = %q, want it to say the key is missing", f.Title)
	}
	if f.Scanner != finding.ScannerConfig {
		t.Errorf("scanner = %v, want config", f.Scanner)
	}
}

func TestScanDriftedValueIsWarning(t *testing.T) {
	findings := scanWith(t,
		map[string]string{"DB_POOL_SIZE": "3"},
		map[string]string{"DB_POOL_SIZE": "10"},
	)

	f := findByTitlePart(findings, "DB_POOL_SIZE")
	if f == nil {
		t.Fatalf("no finding for drifted value, findings: %+v", findings)
	}
	if f.Severity != finding.Warning {
		t.Errorf("severity = %v, want WARNING", f.Severity)
	}
	if !strings.Contains(f.Title, "expected: 10") || !strings.Contains(f.Title, "observed: 3") {
		t.Errorf("title = %q, want expected/observed values", f.Title)
	}
}

func TestScanExtraKeyIsInfo(t *testing.T) {
	findings := scanWith(t,
		map[string]string{"DB_HOST": "x", "NEW_FLAG": "on"},
		map[string]string{"DB_HOST": "x"},
	)

	f := findByTitlePart(findings, "NEW_FLAG")
	if f == nil {
		t.Fatalf("no finding for extra key, findings: %+v", findings)
	}
	if f.Severity != finding.Info {
		t.Errorf("severity = %v, want INFO", f.Severity)
	}
}

func TestScanRedactsSecretValues(t *testing.T) {
	findings := scanWith(t,
		map[string]string{"API_SECRET_KEY": "leaked-observed"},
		map[string]string{"API_SECRET_KEY": "leaked-expected"},
	)

	f := findByTitlePart(findings, "API_SECRET_KEY")
	if f == nil {
		t.Fatalf("no finding for drifted secret, findings: %+v", findings)
	}
	if strings.Contains(f.Title, "leaked") {
		t.Errorf("title leaks secret value: %q", f.Title)
	}
	if !strings.Contains(f.Title, "[REDACTED]") {
		t.Errorf("title = %q, want [REDACTED] placeholder", f.Title)
	}
	for _, v := range f.Detail {
		if s, ok := v.(string); ok && strings.Contains(s, "leaked") {
			t.Errorf("detail leaks secret value: %v", f.Detail)
		}
	}
}

func TestScanAdapterErrorPropagates(t *testing.T) {
	a := stubAdapter{err: errors.New("unreadable")}
	s := NewWithSources(testCfg(), []adapter.Adapter{a}, map[string]string{"K": "v"})
	if _, err := s.Scan(); err == nil {
		t.Fatal("Scan() error = nil, want adapter error")
	}
}

func TestScannerName(t *testing.T) {
	if got := NewWithSources(testCfg(), nil, nil).Name(); got != "config" {
		t.Errorf("Name() = %q, want config", got)
	}
}

func TestNewLoadsExpectedFromEnvFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DB_POOL_SIZE=3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected.env"), []byte("DB_POOL_SIZE=10\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.ConfigConfig{
		Sources:  []string{".env"},
		Expected: "expected.env",
	}
	s, err := New(cfg, dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if f := findByTitlePart(findings, "DB_POOL_SIZE"); f == nil {
		t.Errorf("drift between .env and expected.env not detected: %+v", findings)
	}
}

func TestNewLoadsExpectedFromTOML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DB_POOL_SIZE=3\nDEBUG=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	toml := "DB_POOL_SIZE = 10\nDEBUG = true\n\n[cache]\nttl = 60\n"
	if err := os.WriteFile(filepath.Join(dir, "expected.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.ConfigConfig{
		Sources:  []string{".env"},
		Expected: "expected.toml",
	}
	s, err := New(cfg, dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	// numeric TOML value compares against the .env string form
	if f := findByTitlePart(findings, "DB_POOL_SIZE"); f == nil {
		t.Errorf("drift not detected from TOML expected: %+v", findings)
	}
	// nested tables flatten to dotted keys and count as missing in .env
	if f := findByTitlePart(findings, "cache.ttl"); f == nil {
		t.Errorf("nested TOML key not flattened/diffed: %+v", findings)
	}
	// equal values (DEBUG) must not be flagged
	if f := findByTitlePart(findings, "DEBUG"); f != nil {
		t.Errorf("equal value flagged as drift: %+v", f)
	}
}

func TestNewNoExpectedConfiguredScansNothing(t *testing.T) {
	s, err := New(config.ConfigConfig{Sources: []string{".env"}}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("no expected file configured: findings = %+v, want none", findings)
	}
}

func TestNewMissingExpectedFileErrors(t *testing.T) {
	cfg := config.ConfigConfig{Sources: []string{".env"}, Expected: "nope.env"}
	if _, err := New(cfg, t.TempDir()); err == nil {
		t.Fatal("New() error = nil, want error for configured-but-missing expected file")
	}
}

func TestNewYAMLSourceAndExpected(t *testing.T) {
	dir := t.TempDir()
	observed := "database:\n  pool_size: 3\ncache:\n  ttl: 60\n"
	if err := os.WriteFile(filepath.Join(dir, "prod.yaml"), []byte(observed), 0o644); err != nil {
		t.Fatal(err)
	}
	expected := "database:\n  pool_size: 10\ncache:\n  ttl: 60\n"
	if err := os.WriteFile(filepath.Join(dir, "expected.yaml"), []byte(expected), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.ConfigConfig{
		Sources:  []string{"prod.yaml"},
		Expected: "expected.yaml",
	}
	s, err := New(cfg, dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if f := findByTitlePart(findings, "database.pool_size"); f == nil {
		t.Errorf("YAML drift not detected: %+v", findings)
	}
	if f := findByTitlePart(findings, "cache.ttl"); f != nil {
		t.Errorf("equal YAML value flagged: %+v", f)
	}
}

func TestNewTOMLSourceDiffsAgainstTOMLExpected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prod.toml"), []byte("[cache]\nttl = 30\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected.toml"), []byte("[cache]\nttl = 60\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.ConfigConfig{
		Sources:  []string{"prod.toml"},
		Expected: "expected.toml",
	}
	s, err := New(cfg, dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	f := findByTitlePart(findings, "cache.ttl")
	if f == nil {
		t.Fatalf("TOML source drift not detected: %+v", findings)
	}
	if !strings.Contains(f.Title, "drifted") {
		t.Errorf("finding = %q, want a drift finding", f.Title)
	}
}
