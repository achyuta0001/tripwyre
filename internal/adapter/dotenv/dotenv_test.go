package dotenv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

const envFixture = `# database settings
DB_HOST=localhost
DB_POOL_SIZE=10

export API_URL=https://api.example.com
QUOTED="hello world"
SINGLE='single quoted'
WITH_COMMENT=value # trailing comment
EMPTY=
SPACED = padded
`

func writeEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func valueOf(records []adapter.RawRecord, key string) (string, bool) {
	for _, r := range records {
		if r.Payload["key"] == key {
			v, _ := r.Payload["value"].(string)
			return v, true
		}
	}
	return "", false
}

func TestCollectParsesEnvFile(t *testing.T) {
	a := New(writeEnv(t, envFixture))

	records, err := a.Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 8 {
		t.Fatalf("got %d records, want 8: %+v", len(records), records)
	}

	want := map[string]string{
		"DB_HOST":      "localhost",
		"DB_POOL_SIZE": "10",
		"API_URL":      "https://api.example.com", // export prefix stripped
		"QUOTED":       "hello world",             // double quotes stripped
		"SINGLE":       "single quoted",           // single quotes stripped
		"WITH_COMMENT": "value",                   // trailing comment stripped
		"EMPTY":        "",
		"SPACED":       "padded", // whitespace around = trimmed
	}
	for key, wantVal := range want {
		got, ok := valueOf(records, key)
		if !ok {
			t.Errorf("key %s missing from records", key)
			continue
		}
		if got != wantVal {
			t.Errorf("%s = %q, want %q", key, got, wantVal)
		}
	}
}

func TestCollectMissingFileErrors(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), ".env"))
	if _, err := a.Collect(); err == nil {
		t.Fatal("Collect() error = nil, want error for missing file")
	}
}

func TestName(t *testing.T) {
	if got := New("x").Name(); got != "dotenv" {
		t.Errorf("Name() = %q, want dotenv", got)
	}
}
