package pip

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRequirements(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCollectParsesPinnedRequirements(t *testing.T) {
	path := writeRequirements(t, "requests==2.31.0\nflask==3.0.2\n")

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("Collect() = %d records, want 2", len(records))
	}

	got := map[string]string{}
	for _, r := range records {
		if eco := r.Payload["ecosystem"]; eco != "PyPI" {
			t.Errorf("ecosystem = %v, want PyPI", eco)
		}
		got[r.Payload["name"].(string)] = r.Payload["version"].(string)
	}
	if got["requests"] != "2.31.0" || got["flask"] != "3.0.2" {
		t.Errorf("parsed packages = %v, want requests 2.31.0 and flask 3.0.2", got)
	}
}

func TestCollectSkipsCommentsBlanksAndOptions(t *testing.T) {
	path := writeRequirements(t, `# base requirements
-r dev-requirements.txt
--extra-index-url https://example.com/simple

requests==2.31.0  # http client
`)

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Collect() = %d records, want 1 (comments/options/blanks skipped)", len(records))
	}
	if records[0].Payload["name"] != "requests" || records[0].Payload["version"] != "2.31.0" {
		t.Errorf("record = %v, want requests 2.31.0 (inline comment stripped)", records[0].Payload)
	}
}

func TestCollectStripsExtrasAndMarkers(t *testing.T) {
	path := writeRequirements(t, `requests[security]==2.31.0
uvloop==0.19.0; sys_platform != "win32"
`)

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("Collect() = %d records, want 2", len(records))
	}
	got := map[string]string{}
	for _, r := range records {
		got[r.Payload["name"].(string)] = r.Payload["version"].(string)
	}
	if got["requests"] != "2.31.0" {
		t.Errorf("extras entry parsed as %v, want name without [security]", got)
	}
	if got["uvloop"] != "0.19.0" {
		t.Errorf("marker entry parsed as %v, want version without marker", got)
	}
}

func TestCollectSkipsUnpinnedSpecifiers(t *testing.T) {
	path := writeRequirements(t, `flask>=2.0
django~=4.2
requests==2.31.0
`)

	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	// Only exact pins map to a single version OSV can check.
	if len(records) != 1 || records[0].Payload["name"] != "requests" {
		t.Errorf("records = %v, want only the pinned requests entry", records)
	}
}

func TestCollectMissingFileErrors(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope.txt")).Collect(); err == nil {
		t.Fatal("Collect() error = nil, want read error")
	}
}
