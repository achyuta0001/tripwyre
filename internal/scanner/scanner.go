package scanner

import "github.com/achyuta0001/tripwyre/internal/finding"

// Scanner is implemented by each domain scanner (deps, config, logs).
type Scanner interface {
	Name() string
	Scan() ([]finding.Finding, error)
}
