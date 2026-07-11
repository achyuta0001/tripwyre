package structured

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func collectKV(t *testing.T, path string) map[string]string {
	t.Helper()
	records, err := New(path).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	kv := map[string]string{}
	for _, r := range records {
		if r.Type != "config-kv" {
			t.Errorf("record type = %q, want config-kv", r.Type)
		}
		kv[r.Payload["key"].(string)] = r.Payload["value"].(string)
	}
	return kv
}

func TestCollectFlattensYAML(t *testing.T) {
	path := writeFile(t, "app.yaml", `
database:
  pool_size: 10
  host: db.internal
cache:
  ttl: 60
debug: false
`)

	kv := collectKV(t, path)
	want := map[string]string{
		"database.pool_size": "10",
		"database.host":      "db.internal",
		"cache.ttl":          "60",
		"debug":              "false",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q (all: %v)", k, kv[k], v, kv)
		}
	}
}

func TestCollectFlattensTOML(t *testing.T) {
	path := writeFile(t, "app.toml", `debug = true

[cache]
ttl = 60
`)

	kv := collectKV(t, path)
	if kv["cache.ttl"] != "60" || kv["debug"] != "true" {
		t.Errorf("kv = %v, want cache.ttl=60 and debug=true", kv)
	}
}

func TestFlattenFileYAMLAndTOMLAgree(t *testing.T) {
	yamlKV, err := FlattenFile(writeFile(t, "a.yml", "cache:\n  ttl: 60\n"))
	if err != nil {
		t.Fatalf("FlattenFile(yaml) error = %v", err)
	}
	tomlKV, err := FlattenFile(writeFile(t, "a.toml", "[cache]\nttl = 60\n"))
	if err != nil {
		t.Fatalf("FlattenFile(toml) error = %v", err)
	}
	if yamlKV["cache.ttl"] != "60" || tomlKV["cache.ttl"] != "60" {
		t.Errorf("yaml = %v, toml = %v; both must flatten to cache.ttl=60", yamlKV, tomlKV)
	}
}

func TestCollectMissingFileErrors(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope.yaml")).Collect(); err == nil {
		t.Fatal("Collect() error = nil, want read error")
	}
}

func TestCollectMalformedYAMLErrors(t *testing.T) {
	path := writeFile(t, "bad.yaml", "key: [unclosed\n  nope")
	if _, err := New(path).Collect(); err == nil {
		t.Fatal("Collect() error = nil, want parse error")
	}
}
