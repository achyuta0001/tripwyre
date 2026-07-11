// Package jsonlog reads JSON-lines log files (one JSON object per line)
// and emits RawRecords with the same payload shape as the plaintext
// logfile adapter, so the log scanner treats both identically. Lines
// that aren't valid JSON objects are skipped, not errors — mixed files
// are common when a service switches log formats.
package jsonlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

// Adapter reads a single JSON-lines log file at a fixed path.
type Adapter struct {
	path string
}

func New(path string) *Adapter {
	return &Adapter{path: path}
}

func (a *Adapter) Name() string { return "jsonlog" }

// field-name variants seen across common loggers (zap, logrus, pino,
// bunyan, stackdriver); first match wins.
var (
	timestampKeys = []string{"timestamp", "@timestamp", "time", "ts"}
	levelKeys     = []string{"level", "severity", "lvl"}
	messageKeys   = []string{"message", "msg"}
)

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
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		records = append(records, a.record(line, entry))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.path, err)
	}
	return records, nil
}

func (a *Adapter) record(line string, entry map[string]any) adapter.RawRecord {
	payload := map[string]any{
		"level":   extractLevel(entry),
		"message": extractString(entry, messageKeys),
	}
	if ts, ok := extractTimestamp(entry); ok {
		payload["timestamp"] = ts
	}
	return adapter.RawRecord{
		Source:  a.path,
		Type:    "log-line",
		Payload: payload,
		Raw:     line,
	}
}

func extractString(entry map[string]any, keys []string) string {
	for _, k := range keys {
		if s, ok := entry[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func extractLevel(entry map[string]any) string {
	level := strings.ToUpper(extractString(entry, levelKeys))
	if level == "WARNING" {
		level = "WARN"
	}
	return level
}

var timestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
}

func extractTimestamp(entry map[string]any) (time.Time, bool) {
	for _, k := range timestampKeys {
		switch v := entry[k].(type) {
		case string:
			for _, layout := range timestampLayouts {
				if ts, err := time.Parse(layout, v); err == nil {
					return ts.UTC(), true
				}
			}
		case float64:
			// epoch seconds (zap default); fractional part = sub-second
			sec, frac := math.Modf(v)
			return time.Unix(int64(sec), int64(frac*float64(time.Second))).UTC(), true
		}
	}
	return time.Time{}, false
}
