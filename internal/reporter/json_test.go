package reporter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/achyuta0001/tripwyre/internal/finding"
)

type decodedReport struct {
	Summary struct {
		Total    int `json:"total"`
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
		Info     int `json:"info"`
	} `json:"summary"`
	Findings []struct {
		Severity  string         `json:"severity"`
		Scanner   string         `json:"scanner"`
		Title     string         `json:"title"`
		Detail    map[string]any `json:"detail"`
		Timestamp time.Time      `json:"timestamp"`
	} `json:"findings"`
}

func TestJSONSummarize(t *testing.T) {
	findings := []finding.Finding{
		{
			Severity:  finding.Critical,
			Scanner:   finding.ScannerDeps,
			Title:     "lodash 4.17.20 — 5 CVEs",
			Detail:    map[string]any{"package": "lodash"},
			Timestamp: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
		},
		{Severity: finding.Warning, Scanner: finding.ScannerConfig, Title: "drift"},
	}

	out, err := NewJSONReporter().Summarize(findings)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}

	var rep decodedReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if rep.Summary.Total != 2 || rep.Summary.Critical != 1 || rep.Summary.Warning != 1 {
		t.Errorf("summary = %+v, want total 2, critical 1, warning 1", rep.Summary)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.Severity != "CRITICAL" || f.Scanner != "deps" || f.Title != "lodash 4.17.20 — 5 CVEs" {
		t.Errorf("first finding = %+v, want CRITICAL/deps/lodash title", f)
	}
	if f.Detail["package"] != "lodash" {
		t.Errorf("detail = %v, want package=lodash", f.Detail)
	}
}

func TestJSONSummarizeEmptyIsValidWithEmptyArray(t *testing.T) {
	out, err := NewJSONReporter().Summarize(nil)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	// consumers must get [] rather than null
	if string(raw["findings"]) != "[]" {
		t.Errorf("findings = %s, want []", raw["findings"])
	}
}
