package jsonlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCollectParsesJSONLines(t *testing.T) {
	path := writeLog(t, `{"timestamp":"2026-07-11T03:00:01Z","level":"error","message":"db connection refused"}
{"timestamp":"2026-07-11T03:00:02Z","level":"info","message":"request served"}
`)

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("Collect() = %d records, want 2", len(records))
	}

	r := records[0]
	if r.Payload["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR (uppercased)", r.Payload["level"])
	}
	if r.Payload["message"] != "db connection refused" {
		t.Errorf("message = %v, want db connection refused", r.Payload["message"])
	}
	ts, ok := r.Payload["timestamp"].(time.Time)
	if !ok || !ts.Equal(time.Date(2026, 7, 11, 3, 0, 1, 0, time.UTC)) {
		t.Errorf("timestamp = %v, want 2026-07-11T03:00:01Z", r.Payload["timestamp"])
	}
}

func TestCollectAlternateFieldNames(t *testing.T) {
	// zap-style: ts as epoch seconds, msg, lvl uppercase already
	path := writeLog(t, `{"ts":1782529201.5,"lvl":"WARNING","msg":"pool exhausted"}
{"time":"2026-07-11T03:00:05Z","severity":"fatal","message":"boom"}
`)

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("Collect() = %d records, want 2", len(records))
	}

	if records[0].Payload["level"] != "WARN" {
		t.Errorf("level = %v, want WARN (WARNING normalized)", records[0].Payload["level"])
	}
	if records[0].Payload["message"] != "pool exhausted" {
		t.Errorf("message = %v, want pool exhausted", records[0].Payload["message"])
	}
	if ts, ok := records[0].Payload["timestamp"].(time.Time); !ok || ts.Unix() != 1782529201 {
		t.Errorf("epoch timestamp = %v, want unix 1782529201", records[0].Payload["timestamp"])
	}

	if records[1].Payload["level"] != "FATAL" {
		t.Errorf("level = %v, want FATAL", records[1].Payload["level"])
	}
}

func TestCollectSkipsNonJSONLines(t *testing.T) {
	path := writeLog(t, `not json at all
{"level":"error","message":"real entry"}

`)

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 1 || records[0].Payload["message"] != "real entry" {
		t.Errorf("records = %v, want only the valid JSON entry", records)
	}
}

func TestCollectMissingFileErrors(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope.jsonl")).Collect(); err == nil {
		t.Fatal("Collect() error = nil, want read error")
	}
}
