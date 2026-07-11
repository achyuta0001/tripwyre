package reporter

import (
	"encoding/json"

	"github.com/achyuta0001/tripwyre/internal/finding"
)

// JSONReporter renders findings as machine-readable JSON, for piping
// into jq, CI annotations, or external dashboards.
type JSONReporter struct{}

func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

type jsonReport struct {
	Summary  jsonSummary       `json:"summary"`
	Findings []finding.Finding `json:"findings"`
}

func (r *JSONReporter) Summarize(findings []finding.Finding) (string, error) {
	if findings == nil {
		findings = []finding.Finding{} // marshal as [], not null
	}

	counts := map[finding.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	report := jsonReport{
		Summary: jsonSummary{
			Total:    len(findings),
			Critical: counts[finding.Critical],
			Warning:  counts[finding.Warning],
			Info:     counts[finding.Info],
		},
		Findings: findings,
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}
