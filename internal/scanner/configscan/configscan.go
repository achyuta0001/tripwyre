// Package configscan detects drift between an expected config state and
// the observed state of one or more config sources (.env files, ...).
package configscan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/achyuta0001/tripwyre/internal/adapter"
	"github.com/achyuta0001/tripwyre/internal/adapter/dotenv"
	"github.com/achyuta0001/tripwyre/internal/adapter/structured"
	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
)

const redacted = "[REDACTED]"

type Scanner struct {
	cfg      config.ConfigConfig
	adapters []adapter.Adapter
	expected map[string]string
	redact   []*regexp.Regexp
}

// New builds the production scanner for a project directory: one adapter
// per configured source that exists in dir — .toml/.yaml/.yml sources
// flatten to dotted keys via the structured adapter, anything else
// parses as .env — and the expected state parsed from cfg.Expected with
// the same extension rules. An empty cfg.Expected disables drift
// detection; a configured-but-missing expected file is an error,
// because silently skipping it would hide every drift.
func New(cfg config.ConfigConfig, dir string) (*Scanner, error) {
	var adapters []adapter.Adapter
	for _, src := range cfg.Sources {
		path := filepath.Join(dir, src)
		if _, err := os.Stat(path); err == nil {
			adapters = append(adapters, sourceAdapter(path))
		}
	}

	var expected map[string]string
	if cfg.Expected != "" {
		var err error
		expected, err = loadExpected(filepath.Join(dir, cfg.Expected))
		if err != nil {
			return nil, fmt.Errorf("expected config: %w", err)
		}
	}

	return NewWithSources(cfg, adapters, expected), nil
}

// NewWithSources wires explicit adapters and expected state; used by tests.
func NewWithSources(cfg config.ConfigConfig, adapters []adapter.Adapter, expected map[string]string) *Scanner {
	var redact []*regexp.Regexp
	for _, p := range cfg.RedactPatterns {
		if re, err := regexp.Compile(p); err == nil {
			redact = append(redact, re)
		}
	}
	return &Scanner{cfg: cfg, adapters: adapters, expected: expected, redact: redact}
}

func (s *Scanner) Name() string { return "config" }

func (s *Scanner) Scan() ([]finding.Finding, error) {
	if len(s.expected) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	for _, a := range s.adapters {
		observed, source, err := collectKV(a)
		if err != nil {
			return nil, fmt.Errorf("%s adapter: %w", a.Name(), err)
		}
		findings = append(findings, s.diff(source, observed)...)
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	return findings, nil
}

func collectKV(a adapter.Adapter) (map[string]string, string, error) {
	records, err := a.Collect()
	if err != nil {
		return nil, "", err
	}
	kv := make(map[string]string, len(records))
	var source string
	for _, r := range records {
		key, _ := r.Payload["key"].(string)
		value, _ := r.Payload["value"].(string)
		if key != "" {
			kv[key] = value
		}
		source = r.Source
	}
	return kv, source, nil
}

func (s *Scanner) diff(source string, observed map[string]string) []finding.Finding {
	var findings []finding.Finding

	for key, want := range s.expected {
		got, present := observed[key]
		switch {
		case !present:
			findings = append(findings, finding.Finding{
				Severity: finding.Warning,
				Scanner:  finding.ScannerConfig,
				Title:    fmt.Sprintf("%s missing in %s, present in expected", key, source),
				Detail: map[string]any{
					"key":      key,
					"source":   source,
					"expected": s.display(key, want),
				},
				Timestamp: time.Now(),
			})
		case got != want:
			findings = append(findings, finding.Finding{
				Severity: finding.Warning,
				Scanner:  finding.ScannerConfig,
				Title: fmt.Sprintf("%s drifted in %s (expected: %s, observed: %s)",
					key, source, s.display(key, want), s.display(key, got)),
				Detail: map[string]any{
					"key":      key,
					"source":   source,
					"expected": s.display(key, want),
					"observed": s.display(key, got),
				},
				Timestamp: time.Now(),
			})
		}
	}

	for key := range observed {
		if _, ok := s.expected[key]; !ok {
			findings = append(findings, finding.Finding{
				Severity: finding.Info,
				Scanner:  finding.ScannerConfig,
				Title:    fmt.Sprintf("%s present in %s, not in expected", key, source),
				Detail: map[string]any{
					"key":    key,
					"source": source,
				},
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

// display returns the value, or the redaction placeholder if the key
// matches any configured redact pattern. Values of secret-looking keys
// must never reach titles, details, or reporters.
func (s *Scanner) display(key, value string) string {
	for _, re := range s.redact {
		if re.MatchString(key) {
			return redacted
		}
	}
	return value
}

// sourceAdapter picks the adapter for a config source by extension:
// structured formats flatten to dotted keys, everything else is .env.
func sourceAdapter(path string) adapter.Adapter {
	if isStructured(path) {
		return structured.New(path)
	}
	return dotenv.New(path)
}

func isStructured(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml", ".yaml", ".yml":
		return true
	}
	return false
}

func loadExpected(path string) (map[string]string, error) {
	if isStructured(path) {
		return structured.FlattenFile(path)
	}
	return dotenv.ParseFile(path)
}
