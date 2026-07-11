// Package structured reads structured config files (TOML, YAML) and
// emits one RawRecord per leaf value, with nested tables flattened to
// dotted string keys: [cache] ttl = 60 → "cache.ttl" = "60". This makes
// structured configs diffable with the same key/value rules as .env.
package structured

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	yaml "go.yaml.in/yaml/v4"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a single .toml/.yaml/.yml file at a fixed path.
type Adapter struct {
	path string
}

func New(path string) *Adapter {
	return &Adapter{path: path}
}

func (a *Adapter) Name() string { return "structured" }

func (a *Adapter) Collect() ([]adapter.RawRecord, error) {
	kv, err := FlattenFile(a.path)
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

// FlattenFile parses a TOML or YAML file (by extension) into a flat map
// of dotted string keys. Exposed so the config scanner can load its
// expected-state file with the same rules.
func FlattenFile(path string) (map[string]string, error) {
	var raw map[string]any

	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		if _, err := toml.DecodeFile(path, &raw); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	case ".yaml", ".yml":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("%s: unsupported structured config extension", path)
	}

	kv := make(map[string]string)
	flatten("", raw, kv)
	return kv, nil
}

func flatten(prefix string, raw map[string]any, out map[string]string) {
	for key, value := range raw {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}
		if nested, ok := value.(map[string]any); ok {
			flatten(full, nested, out)
			continue
		}
		out[full] = fmt.Sprintf("%v", value)
	}
}
