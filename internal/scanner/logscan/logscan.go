// Package logscan detects anomalies in log records: error-rate spikes
// inside fixed time windows and recurring errors clustered by normalized
// message shape.
package logscan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/achyuta0001/tripwyre/internal/adapter"
	"github.com/achyuta0001/tripwyre/internal/adapter/jsonlog"
	"github.com/achyuta0001/tripwyre/internal/adapter/logfile"
	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
)

// spikeWindow is the fixed bucketing window for error-rate spikes.
const spikeWindow = 15 * time.Minute

type Scanner struct {
	cfg      config.LogsConfig
	adapters []adapter.Adapter
}

// New builds the production scanner: one adapter per configured source
// that exists in dir — .json/.jsonl sources parse as JSON lines, the
// rest as plaintext. Missing log files are skipped so `scan` works
// before any logs exist.
func New(cfg config.LogsConfig, dir string) *Scanner {
	var adapters []adapter.Adapter
	for _, src := range cfg.Sources {
		path := filepath.Join(dir, src)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json", ".jsonl":
			adapters = append(adapters, jsonlog.New(path))
		default:
			adapters = append(adapters, logfile.New(path))
		}
	}
	return NewWithSources(cfg, adapters)
}

// NewWithSources wires explicit adapters; used by tests.
func NewWithSources(cfg config.LogsConfig, adapters []adapter.Adapter) *Scanner {
	return &Scanner{cfg: cfg, adapters: adapters}
}

func (s *Scanner) Name() string { return "logs" }

// errRecord is a parsed error-level log line.
type errRecord struct {
	source    string
	message   string
	timestamp time.Time // zero if the line had no parseable timestamp
}

func (s *Scanner) Scan() ([]finding.Finding, error) {
	var errs []errRecord
	for _, a := range s.adapters {
		records, err := a.Collect()
		if err != nil {
			return nil, fmt.Errorf("%s adapter: %w", a.Name(), err)
		}
		for _, r := range records {
			level, _ := r.Payload["level"].(string)
			if level != "ERROR" && level != "FATAL" {
				continue
			}
			message, _ := r.Payload["message"].(string)
			ts, _ := r.Payload["timestamp"].(time.Time)
			errs = append(errs, errRecord{source: r.Source, message: message, timestamp: ts})
		}
	}

	var findings []finding.Finding
	findings = append(findings, s.spikeFindings(errs)...)
	findings = append(findings, s.clusterFindings(errs)...)

	// TODO: slow request detection (parse duration fields)

	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	return findings, nil
}

// spikeFindings flags any 15-minute window in which a single source
// logged at least ErrorSpikeThreshold errors.
func (s *Scanner) spikeFindings(errs []errRecord) []finding.Finding {
	if s.cfg.ErrorSpikeThreshold <= 0 {
		return nil
	}

	type bucket struct {
		source string
		window time.Time
	}
	counts := map[bucket]int{}
	for _, e := range errs {
		if e.timestamp.IsZero() {
			continue // can't bucket lines without timestamps
		}
		counts[bucket{e.source, e.timestamp.Truncate(spikeWindow)}]++
	}

	var findings []finding.Finding
	for b, n := range counts {
		if n < s.cfg.ErrorSpikeThreshold {
			continue
		}
		start, end := b.window, b.window.Add(spikeWindow)
		findings = append(findings, finding.Finding{
			Severity: finding.Warning,
			Scanner:  finding.ScannerLogs,
			Title: fmt.Sprintf("error spike in %s — %d errors between %s–%s UTC",
				b.source, n, start.Format("15:04"), end.Format("15:04")),
			Detail: map[string]any{
				"source":       b.source,
				"count":        n,
				"window_start": start,
				"window_end":   end,
				"threshold":    s.cfg.ErrorSpikeThreshold,
			},
			Timestamp: time.Now(),
		})
	}
	return findings
}

// clusterFindings groups errors whose messages differ only in volatile
// parts (numbers, hex IDs) and flags clusters of ClusterMinSize or more.
func (s *Scanner) clusterFindings(errs []errRecord) []finding.Finding {
	if s.cfg.ClusterMinSize <= 0 {
		return nil
	}

	type cluster struct {
		count   int
		source  string
		example string
	}
	clusters := map[string]*cluster{}
	for _, e := range errs {
		key := normalize(e.message)
		if key == "" {
			continue
		}
		c, ok := clusters[key]
		if !ok {
			c = &cluster{source: e.source, example: e.message}
			clusters[key] = c
		}
		c.count++
	}

	var findings []finding.Finding
	for key, c := range clusters {
		if c.count < s.cfg.ClusterMinSize {
			continue
		}
		findings = append(findings, finding.Finding{
			Severity: finding.Info,
			Scanner:  finding.ScannerLogs,
			Title:    fmt.Sprintf("recurring error in %s — %d× %q", c.source, c.count, key),
			Detail: map[string]any{
				"source":  c.source,
				"count":   c.count,
				"pattern": key,
			},
			Context:   c.example,
			Timestamp: time.Now(),
		})
	}
	return findings
}

var (
	hexRe    = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	numberRe = regexp.MustCompile(`\d+`)
	spaceRe  = regexp.MustCompile(`\s+`)
)

// normalize strips the volatile parts of an error message (IDs, counts,
// durations) so repeated occurrences of the same failure share a key.
// This is deliberately simpler than edit-distance clustering; revisit if
// real-world messages group poorly.
func normalize(message string) string {
	m := strings.ToLower(strings.TrimSpace(message))
	m = hexRe.ReplaceAllString(m, "#")
	m = numberRe.ReplaceAllString(m, "#")
	m = spaceRe.ReplaceAllString(m, " ")
	return m
}
