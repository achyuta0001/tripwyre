package reporter

import (
	"strings"
	"testing"

	"github.com/achyuta0001/tripwyre/internal/finding"
)

func TestSummarizeEmpty(t *testing.T) {
	out, err := NewTemplateReporter().Summarize(nil)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("output = %q, want it to contain %q", out, "No findings")
	}
}

func TestSummarizeCountsBySeverity(t *testing.T) {
	findings := []finding.Finding{
		{Severity: finding.Critical, Scanner: finding.ScannerDeps, Title: "c1"},
		{Severity: finding.Warning, Scanner: finding.ScannerConfig, Title: "w1"},
		{Severity: finding.Warning, Scanner: finding.ScannerConfig, Title: "w2"},
		{Severity: finding.Info, Scanner: finding.ScannerLogs, Title: "i1"},
	}

	out, err := NewTemplateReporter().Summarize(findings)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if !strings.Contains(out, "4 findings (1 critical, 2 warning, 1 info)") {
		t.Errorf("output = %q, want header with severity counts", out)
	}
}

func TestSummarizeOrdersBySeverity(t *testing.T) {
	// deliberately interleaved input order
	findings := []finding.Finding{
		{Severity: finding.Info, Scanner: finding.ScannerLogs, Title: "info-finding"},
		{Severity: finding.Critical, Scanner: finding.ScannerDeps, Title: "critical-finding"},
		{Severity: finding.Warning, Scanner: finding.ScannerConfig, Title: "warning-finding"},
	}

	out, err := NewTemplateReporter().Summarize(findings)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}

	critIdx := strings.Index(out, "critical-finding")
	warnIdx := strings.Index(out, "warning-finding")
	infoIdx := strings.Index(out, "info-finding")
	if critIdx == -1 || warnIdx == -1 || infoIdx == -1 {
		t.Fatalf("output missing findings: %q", out)
	}
	if !(critIdx < warnIdx && warnIdx < infoIdx) {
		t.Errorf("findings not ordered critical > warning > info in output:\n%s", out)
	}
}
