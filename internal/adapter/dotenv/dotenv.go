// Package dotenv reads .env-style config files and emits one RawRecord
// per key/value pair.
package dotenv

import (
	"fmt"
	"os"
	"strings"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a single .env file at a fixed path.
type Adapter struct {
	path string
}

func New(path string) *Adapter {
	return &Adapter{path: path}
}

func (a *Adapter) Name() string { return "dotenv" }

func (a *Adapter) Collect() ([]adapter.RawRecord, error) {
	kv, err := ParseFile(a.path)
	if err != nil {
		return nil, err
	}

	records := make([]adapter.RawRecord, 0, len(kv))
	for key, value := range kv {
		records = append(records, adapter.RawRecord{
			Source: a.path,
			Type:   "config-kv",
			Payload: map[string]any{
				"key":   key,
				"value": value,
			},
		})
	}
	return records, nil
}

// ParseFile parses a .env file into a key/value map. Exposed so the
// config scanner can parse its expected-state file with the same rules.
func ParseFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	kv := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue // not a KEY=VALUE line
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch {
		case len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"':
			value = value[1 : len(value)-1]
		case len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'':
			value = value[1 : len(value)-1]
		default:
			// unquoted values may carry a trailing comment
			if idx := strings.Index(value, " #"); idx != -1 {
				value = strings.TrimSpace(value[:idx])
			}
		}

		kv[key] = value
	}
	return kv, nil
}
