package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
	"github.com/achyuta0001/tripwyre/internal/scanner"
)

type stubScanner struct {
	findings []finding.Finding
	err      error
}

func (s stubScanner) Name() string                     { return "stub" }
func (s stubScanner) Scan() ([]finding.Finding, error) { return s.findings, s.err }

func buildStubs(scanners ...scanner.Scanner) func(*config.Config) []scanner.Scanner {
	return func(*config.Config) []scanner.Scanner { return scanners }
}

func TestRunScanNoScanners(t *testing.T) {
	var out strings.Builder
	if err := runScan(&out, buildStubs()); err != nil {
		t.Fatalf("runScan() error = %v", err)
	}
	if !strings.Contains(out.String(), "No findings") {
		t.Errorf("output = %q, want it to contain %q", out.String(), "No findings")
	}
}

func TestRunScanRendersFindings(t *testing.T) {
	s := stubScanner{findings: []finding.Finding{
		{Severity: finding.Critical, Scanner: finding.ScannerDeps, Title: "lodash CVE"},
	}}

	var out strings.Builder
	if err := runScan(&out, buildStubs(s)); err != nil {
		t.Fatalf("runScan() error = %v", err)
	}
	if !strings.Contains(out.String(), "lodash CVE") {
		t.Errorf("output = %q, want it to contain finding title", out.String())
	}
}

func TestRunScanPropagatesScannerError(t *testing.T) {
	s := stubScanner{err: errors.New("boom")}

	var out strings.Builder
	err := runScan(&out, buildStubs(s))
	if err == nil {
		t.Fatal("runScan() error = nil, want scanner error")
	}
	if !strings.Contains(err.Error(), "stub") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %q, want it to name the scanner and cause", err)
	}
}

func TestRunScanAppliesFailOn(t *testing.T) {
	prev := failOn
	failOn = "critical"
	defer func() { failOn = prev }()

	s := stubScanner{findings: []finding.Finding{
		{Severity: finding.Critical, Scanner: finding.ScannerDeps, Title: "bad"},
	}}

	var out strings.Builder
	if err := runScan(&out, buildStubs(s)); err == nil {
		t.Fatal("runScan() error = nil, want fail-on error for critical finding")
	}
}

func TestRunScanJSONFormat(t *testing.T) {
	prev := format
	format = "json"
	defer func() { format = prev }()

	s := stubScanner{findings: []finding.Finding{
		{Severity: finding.Warning, Scanner: finding.ScannerDeps, Title: "json-me"},
	}}

	var out strings.Builder
	if err := runScan(&out, buildStubs(s)); err != nil {
		t.Fatalf("runScan() error = %v", err)
	}

	var rep struct {
		Findings []struct {
			Title string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out.String()), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Title != "json-me" {
		t.Errorf("decoded findings = %+v, want the stub finding", rep.Findings)
	}
}

func TestRunScanInvalidFormatErrors(t *testing.T) {
	prev := format
	format = "yaml"
	defer func() { format = prev }()

	var out strings.Builder
	err := runScan(&out, buildStubs())
	if err == nil {
		t.Fatal("runScan() error = nil, want invalid format error")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("error = %q, want it to name the bad format", err)
	}
}
