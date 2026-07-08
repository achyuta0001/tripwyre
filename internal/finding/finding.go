package finding

import "time"

type Severity string

const (
	Critical Severity = "CRITICAL"
	Warning  Severity = "WARNING"
	Info     Severity = "INFO"
)

type Scanner string

const (
	ScannerDeps   Scanner = "deps"
	ScannerConfig Scanner = "config"
	ScannerLogs   Scanner = "logs"
)

// Finding is the canonical output of every scanner.
// Rules engines produce Findings; reporters consume them.
type Finding struct {
	Severity  Severity
	Scanner   Scanner
	Title     string
	Detail    map[string]any
	Context   string    // raw excerpt passed to LLM reporter if enabled
	Timestamp time.Time
}
