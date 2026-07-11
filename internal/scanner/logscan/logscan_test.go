package logscan

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/achyuta0001/tripwyre/internal/adapter"
	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
)

type stubAdapter struct {
	records []adapter.RawRecord
	err     error
}

func (s stubAdapter) Name() string                          { return "stub" }
func (s stubAdapter) Collect() ([]adapter.RawRecord, error) { return s.records, s.err }

func logRecord(ts time.Time, level, message string) adapter.RawRecord {
	payload := map[string]any{"level": level, "message": message}
	if !ts.IsZero() {
		payload["timestamp"] = ts
	}
	return adapter.RawRecord{
		Source:  "app.log",
		Type:    "log-line",
		Payload: payload,
		Raw:     level + " " + message,
	}
}

func testCfg() config.LogsConfig {
	return config.LogsConfig{
		ErrorSpikeThreshold: 5,
		ClusterMinSize:      3,
	}
}

func scanWith(t *testing.T, records []adapter.RawRecord) []finding.Finding {
	t.Helper()
	s := NewWithSources(testCfg(), []adapter.Adapter{stubAdapter{records: records}})
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return findings
}

func findByTitlePart(findings []finding.Finding, part string) *finding.Finding {
	for i := range findings {
		if strings.Contains(findings[i].Title, part) {
			return &findings[i]
		}
	}
	return nil
}

func TestScanErrorSpikeIsWarning(t *testing.T) {
	base := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	var records []adapter.RawRecord
	// 6 errors inside one 15-minute window, threshold 5
	for i := 0; i < 6; i++ {
		records = append(records, logRecord(base.Add(time.Duration(i)*time.Minute), "ERROR", fmt.Sprintf("unique failure %c", 'a'+i)))
	}

	findings := scanWith(t, records)

	f := findByTitlePart(findings, "error spike")
	if f == nil {
		t.Fatalf("no spike finding, findings: %+v", findings)
	}
	if f.Severity != finding.Warning {
		t.Errorf("severity = %v, want WARNING", f.Severity)
	}
	if !strings.Contains(f.Title, "6 errors") {
		t.Errorf("title = %q, want error count", f.Title)
	}
	if !strings.Contains(f.Title, "03:00") || !strings.Contains(f.Title, "03:15") {
		t.Errorf("title = %q, want window bounds 03:00–03:15", f.Title)
	}
	if f.Scanner != finding.ScannerLogs {
		t.Errorf("scanner = %v, want logs", f.Scanner)
	}
}

func TestScanBelowThresholdNoSpike(t *testing.T) {
	base := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	var records []adapter.RawRecord
	for i := 0; i < 4; i++ { // threshold is 5
		records = append(records, logRecord(base.Add(time.Duration(i)*time.Minute), "ERROR", fmt.Sprintf("unique failure %c", 'a'+i)))
	}

	if findings := scanWith(t, records); findByTitlePart(findings, "error spike") != nil {
		t.Errorf("4 errors under threshold 5 should not spike: %+v", findings)
	}
}

func TestScanErrorsAcrossWindowsNoSpike(t *testing.T) {
	base := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	var records []adapter.RawRecord
	// 6 errors spread over 3 hours — never 5 in one window
	for i := 0; i < 6; i++ {
		records = append(records, logRecord(base.Add(time.Duration(i)*30*time.Minute), "ERROR", fmt.Sprintf("unique failure %c", 'a'+i)))
	}

	if findings := scanWith(t, records); findByTitlePart(findings, "error spike") != nil {
		t.Errorf("errors spread across windows should not spike: %+v", findings)
	}
}

func TestScanRecurringErrorsCluster(t *testing.T) {
	base := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	var records []adapter.RawRecord
	// 4 occurrences of the same error differing only in IDs, min cluster 3
	for i := 0; i < 4; i++ {
		records = append(records, logRecord(
			base.Add(time.Duration(i)*time.Hour), // spread out: no spike
			"ERROR",
			fmt.Sprintf("db timeout for request id=%d took %dms", 1000+i, 50+i),
		))
	}

	findings := scanWith(t, records)

	f := findByTitlePart(findings, "recurring error")
	if f == nil {
		t.Fatalf("no cluster finding, findings: %+v", findings)
	}
	if f.Severity != finding.Info {
		t.Errorf("severity = %v, want INFO", f.Severity)
	}
	if !strings.Contains(f.Title, "4×") {
		t.Errorf("title = %q, want occurrence count", f.Title)
	}
	if !strings.Contains(f.Title, "db timeout") {
		t.Errorf("title = %q, want normalized message", f.Title)
	}
}

func TestScanDistinctErrorsDoNotCluster(t *testing.T) {
	base := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	records := []adapter.RawRecord{
		logRecord(base, "ERROR", "disk full on /var"),
		logRecord(base.Add(time.Hour), "ERROR", "connection refused to redis"),
		logRecord(base.Add(2*time.Hour), "ERROR", "nil pointer in handler"),
	}

	if findings := scanWith(t, records); findByTitlePart(findings, "recurring error") != nil {
		t.Errorf("distinct errors should not cluster: %+v", findings)
	}
}

func TestScanNonErrorLevelsIgnored(t *testing.T) {
	base := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	var records []adapter.RawRecord
	for i := 0; i < 10; i++ {
		records = append(records, logRecord(base.Add(time.Duration(i)*time.Second), "INFO", "request served"))
	}

	if findings := scanWith(t, records); len(findings) != 0 {
		t.Errorf("INFO lines must not trigger findings: %+v", findings)
	}
}

func TestScanAdapterErrorPropagates(t *testing.T) {
	s := NewWithSources(testCfg(), []adapter.Adapter{stubAdapter{err: errors.New("unreadable")}})
	if _, err := s.Scan(); err == nil {
		t.Fatal("Scan() error = nil, want adapter error")
	}
}

func TestScannerName(t *testing.T) {
	if got := NewWithSources(testCfg(), nil).Name(); got != "logs" {
		t.Errorf("Name() = %q, want logs", got)
	}
}
