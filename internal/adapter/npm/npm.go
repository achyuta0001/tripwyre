// Package npm reads npm package-lock.json files and emits one RawRecord
// per installed dependency.
package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a package-lock.json at a fixed path.
type Adapter struct {
	path string
}

func New(lockfilePath string) *Adapter {
	return &Adapter{path: lockfilePath}
}

func (a *Adapter) Name() string { return "npm" }

type lockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`     // v2/v3
	Dependencies    map[string]lockPackage `json:"dependencies"` // v1
}

type lockPackage struct {
	Version string `json:"version"`
	License string `json:"license"`
	Dev     bool   `json:"dev"`
}

func (a *Adapter) Collect() ([]adapter.RawRecord, error) {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.path, err)
	}

	var lf lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", a.path, err)
	}

	var records []adapter.RawRecord

	if len(lf.Packages) > 0 {
		// lockfile v2/v3: keys are install paths like "node_modules/@scope/name"
		for path, pkg := range lf.Packages {
			name := packageNameFromPath(path)
			if name == "" {
				continue // root package entry or workspace link
			}
			records = append(records, a.record(name, pkg))
		}
		return records, nil
	}

	// lockfile v1 fallback: keys are package names directly
	for name, pkg := range lf.Dependencies {
		records = append(records, a.record(name, pkg))
	}
	return records, nil
}

func (a *Adapter) record(name string, pkg lockPackage) adapter.RawRecord {
	return adapter.RawRecord{
		Source: a.path,
		Type:   "npm-package",
		Payload: map[string]any{
			"ecosystem": "npm",
			"name":      name,
			"version":   pkg.Version,
			"license":   pkg.License,
			"dev":       pkg.Dev,
		},
	}
}

// packageNameFromPath extracts the package name from a lockfile v2/v3
// install path. "node_modules/@babel/core" → "@babel/core"; nested paths
// keep only the innermost package. Returns "" for the root entry.
func packageNameFromPath(path string) string {
	if path == "" {
		return ""
	}
	const marker = "node_modules/"
	idx := strings.LastIndex(path, marker)
	if idx == -1 {
		return "" // workspace or link entry, not an installed dependency
	}
	return path[idx+len(marker):]
}
