package cmd

import (
	"testing"

	"github.com/achyuta0001/tripwyre/internal/finding"
)

func TestCheckFailOn(t *testing.T) {
	crit := finding.Finding{Severity: finding.Critical, Scanner: finding.ScannerDeps, Title: "c"}
	warn := finding.Finding{Severity: finding.Warning, Scanner: finding.ScannerConfig, Title: "w"}
	info := finding.Finding{Severity: finding.Info, Scanner: finding.ScannerLogs, Title: "i"}

	tests := []struct {
		name      string
		findings  []finding.Finding
		threshold string
		wantErr   bool
	}{
		{"empty threshold never fails", []finding.Finding{crit}, "", false},
		{"invalid threshold errors", nil, "bogus", true},
		{"no findings passes", nil, "info", false},
		{"below threshold passes", []finding.Finding{info, warn}, "critical", false},
		{"at threshold fails", []finding.Finding{warn}, "warning", true},
		{"above threshold fails", []finding.Finding{crit}, "warning", true},
		{"info threshold catches everything", []finding.Finding{info}, "info", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkFailOn(tt.findings, tt.threshold)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkFailOn(%v, %q) error = %v, wantErr %v", tt.findings, tt.threshold, err, tt.wantErr)
			}
		})
	}
}
