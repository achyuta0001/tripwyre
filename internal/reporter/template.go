package reporter

import (
	"fmt"
	"strings"

	"github.com/achyuta0001/tripwyre/internal/finding"
)

// TemplateReporter renders findings as a structured text report.
// No LLM required — free by default.
type TemplateReporter struct{}

func NewTemplateReporter() *TemplateReporter {
	return &TemplateReporter{}
}

func (r *TemplateReporter) Summarize(findings []finding.Finding) (string, error) {
	if len(findings) == 0 {
		return "No findings. All clear.\n", nil
	}

	var sb strings.Builder

	counts := map[finding.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	sb.WriteString(fmt.Sprintf(
		"tripwyre — %d findings (%d critical, %d warning, %d info)\n\n",
		len(findings),
		counts[finding.Critical],
		counts[finding.Warning],
		counts[finding.Info],
	))

	for _, sev := range []finding.Severity{finding.Critical, finding.Warning, finding.Info} {
		for _, f := range findings {
			if f.Severity != sev {
				continue
			}
			sb.WriteString(fmt.Sprintf("%-10s [%s]  %s\n", f.Severity, f.Scanner, f.Title))
		}
	}

	return sb.String(), nil
}
