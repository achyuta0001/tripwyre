// Package logfile reads plaintext log files and emits one RawRecord per
// line, with best-effort timestamp and level extraction.
package logfile

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a single plaintext log file at a fixed path.
type Adapter struct {
	path string
}

func New(path string) *Adapter {
	return &Adapter{path: path}
}

func (a *Adapter) Name() string { return "logfile" }

var (
	// ISO-8601-ish: 2026-07-11T03:00:01Z or 2026-07-11 03:00:01
	timestampRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	levelRe     = regexp.MustCompile(`(?i)\b(FATAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\b`)
)

var timestampLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
}

func (a *Adapter) Collect() ([]adapter.RawRecord, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.path, err)
	}
	defer f.Close()

	var records []adapter.RawRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long lines
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		records = append(records, a.record(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.path, err)
	}
	return records, nil
}

func (a *Adapter) record(line string) adapter.RawRecord {
	payload := map[string]any{
		"level":   "",
		"message": strings.TrimSpace(line),
	}

	if m := timestampRe.FindString(line); m != "" {
		if ts, ok := parseTimestamp(m); ok {
			payload["timestamp"] = ts
		}
	}

	if loc := levelRe.FindStringIndex(line); loc != nil {
		level := strings.ToUpper(line[loc[0]:loc[1]])
		if level == "WARNING" {
			level = "WARN"
		}
		payload["level"] = level
		// message = text after the level token, if any
		msg := strings.TrimSpace(strings.TrimLeft(line[loc[1]:], " :-"))
		if msg != "" {
			payload["message"] = msg
		}
	}

	return adapter.RawRecord{
		Source:  a.path,
		Type:    "log-line",
		Payload: payload,
		Raw:     line,
	}
}

func parseTimestamp(s string) (time.Time, bool) {
	normalized := strings.Replace(s, " ", "T", 1)
	for _, layout := range timestampLayouts {
		if ts, err := time.Parse(layout, normalized); err == nil {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}
