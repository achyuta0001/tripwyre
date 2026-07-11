package logfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const logFixture = `2026-07-11T03:00:01Z ERROR auth-service: connection refused to db-pool
2026-07-11 03:00:02 WARN retrying connection
2026-07-11T03:00:03Z INFO request served in 12ms
plain line without timestamp or level
2026-07-11T03:00:04Z error lowercase level also detected
`

func writeLog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCollectParsesLines(t *testing.T) {
	a := New(writeLog(t, logFixture))

	records, err := a.Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 5 {
		t.Fatalf("got %d records, want 5 (one per non-empty line)", len(records))
	}

	first := records[0]
	if first.Payload["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", first.Payload["level"])
	}
	wantTS := time.Date(2026, 7, 11, 3, 0, 1, 0, time.UTC)
	ts, ok := first.Payload["timestamp"].(time.Time)
	if !ok || !ts.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v", first.Payload["timestamp"], wantTS)
	}
	if msg, _ := first.Payload["message"].(string); msg != "auth-service: connection refused to db-pool" {
		t.Errorf("message = %q, want text after level token", msg)
	}
	if first.Raw == "" {
		t.Error("Raw must carry the original line")
	}

	// space-separated timestamp format also parses
	if ts2, ok := records[1].Payload["timestamp"].(time.Time); !ok || ts2.IsZero() {
		t.Errorf("space-separated timestamp not parsed: %v", records[1].Payload["timestamp"])
	}
	if records[1].Payload["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", records[1].Payload["level"])
	}

	// line without timestamp/level still becomes a record
	plain := records[3]
	if plain.Payload["level"] != "" {
		t.Errorf("plain line level = %v, want empty", plain.Payload["level"])
	}
	if _, ok := plain.Payload["timestamp"].(time.Time); ok {
		t.Error("plain line must not fabricate a timestamp")
	}

	// lowercase level tokens normalize to uppercase
	if records[4].Payload["level"] != "ERROR" {
		t.Errorf("lowercase level = %v, want ERROR", records[4].Payload["level"])
	}
}

func TestCollectMissingFileErrors(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "app.log"))
	if _, err := a.Collect(); err == nil {
		t.Fatal("Collect() error = nil, want error for missing file")
	}
}

func TestName(t *testing.T) {
	if got := New("x").Name(); got != "logfile" {
		t.Errorf("Name() = %q, want logfile", got)
	}
}
