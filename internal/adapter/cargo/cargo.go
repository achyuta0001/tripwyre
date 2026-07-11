// Package cargo reads Cargo.lock files and emits one RawRecord per
// registry dependency. Workspace crates (entries without a source) are
// skipped — they're the project itself, not third-party dependencies.
package cargo

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a Cargo.lock at a fixed path.
type Adapter struct {
	path string
}

func New(path string) *Adapter {
	return &Adapter{path: path}
}

func (a *Adapter) Name() string { return "cargo" }

type lockfile struct {
	Packages []lockPackage `toml:"package"`
}

type lockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  string `toml:"source"`
}

func (a *Adapter) Collect() ([]adapter.RawRecord, error) {
	var lf lockfile
	if _, err := toml.DecodeFile(a.path, &lf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", a.path, err)
	}

	var records []adapter.RawRecord
	for _, pkg := range lf.Packages {
		if pkg.Source == "" || pkg.Name == "" || pkg.Version == "" {
			continue
		}
		records = append(records, adapter.RawRecord{
			Source: a.path,
			Type:   "cargo-package",
			Payload: map[string]any{
				"ecosystem": "crates.io",
				"name":      pkg.Name,
				"version":   pkg.Version,
			},
		})
	}
	return records, nil
}
