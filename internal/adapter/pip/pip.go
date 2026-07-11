// Package pip reads pip requirements.txt files and emits one RawRecord
// per exactly-pinned dependency (name==version). Unpinned specifiers
// (>=, ~=, ranges) are skipped: OSV needs a single concrete version.
package pip

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a requirements.txt at a fixed path.
type Adapter struct {
	path string
}

func New(path string) *Adapter {
	return &Adapter{path: path}
}

func (a *Adapter) Name() string { return "pip" }

func (a *Adapter) Collect() ([]adapter.RawRecord, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.path, err)
	}
	defer f.Close()

	var records []adapter.RawRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		name, version, ok := parseRequirement(scanner.Text())
		if !ok {
			continue
		}
		records = append(records, adapter.RawRecord{
			Source: a.path,
			Type:   "pip-package",
			Payload: map[string]any{
				"ecosystem": "PyPI",
				"name":      name,
				"version":   version,
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.path, err)
	}
	return records, nil
}

// parseRequirement extracts name and version from one requirements.txt
// line. Returns ok=false for comments, blanks, pip options (-r, --hash),
// and anything not pinned with ==.
func parseRequirement(line string) (name, version string, ok bool) {
	// strip inline comments and environment markers
	if idx := strings.Index(line, "#"); idx != -1 {
		line = line[:idx]
	}
	if idx := strings.Index(line, ";"); idx != -1 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)

	if line == "" || strings.HasPrefix(line, "-") {
		return "", "", false
	}

	name, version, found := strings.Cut(line, "==")
	if !found || strings.ContainsAny(name, "<>~!") {
		return "", "", false
	}

	// strip extras: requests[security] → requests
	if idx := strings.Index(name, "["); idx != -1 {
		name = name[:idx]
	}

	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
