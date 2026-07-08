package reporter

import "github.com/achyuta0001/tripwyre/internal/finding"

// Synthesizer renders findings into a human-readable report.
// TemplateReporter is the free default.
// LLMReporter is the optional paid upgrade.
type Synthesizer interface {
	Summarize(findings []finding.Finding) (string, error)
}
