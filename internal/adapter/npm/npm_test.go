package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/achyuta0001/tripwyre/internal/adapter"
)

const lockV3 = `{
  "name": "myapp",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "myapp",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
      "license": "MIT"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    },
    "node_modules/jest": {
      "version": "29.0.0",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@babel/core": {
      "version": "7.23.0",
      "license": "MIT"
    }
  }
}`

const lockV1 = `{
  "name": "oldapp",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    },
    "minimist": {
      "version": "0.0.8",
      "dev": true
    }
  }
}`

func writeLock(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordByName(records []adapter.RawRecord, name string) *adapter.RawRecord {
	for i := range records {
		if records[i].Payload["name"] == name {
			return &records[i]
		}
	}
	return nil
}

func TestCollectLockfileV3(t *testing.T) {
	a := New(writeLock(t, lockV3))

	records, err := a.Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	// root package ("") must be excluded
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4: %+v", len(records), records)
	}

	lodash := recordByName(records, "lodash")
	if lodash == nil {
		t.Fatal("lodash record missing")
	}
	if lodash.Payload["version"] != "4.17.20" {
		t.Errorf("lodash version = %v, want 4.17.20", lodash.Payload["version"])
	}
	if lodash.Payload["license"] != "MIT" {
		t.Errorf("lodash license = %v, want MIT", lodash.Payload["license"])
	}
	if lodash.Payload["dev"] != false {
		t.Errorf("lodash dev = %v, want false", lodash.Payload["dev"])
	}

	// scoped package names must strip the node_modules/ prefix but keep the scope
	if babel := recordByName(records, "@babel/core"); babel == nil {
		t.Error("@babel/core record missing — scoped name not parsed correctly")
	}

	// missing license comes through as empty string, dev flag propagates
	if lp := recordByName(records, "left-pad"); lp == nil || lp.Payload["license"] != "" {
		t.Errorf("left-pad license = %v, want empty string", lp.Payload["license"])
	}
	if jest := recordByName(records, "jest"); jest == nil || jest.Payload["dev"] != true {
		t.Error("jest should be marked dev")
	}
}

func TestCollectLockfileV1Fallback(t *testing.T) {
	a := New(writeLock(t, lockV1))

	records, err := a.Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if lodash := recordByName(records, "lodash"); lodash == nil || lodash.Payload["version"] != "4.17.20" {
		t.Errorf("lodash not parsed from v1 lockfile: %+v", records)
	}
}

func TestCollectMissingFileErrors(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "package-lock.json"))
	if _, err := a.Collect(); err == nil {
		t.Fatal("Collect() error = nil, want error for missing lockfile")
	}
}

func TestName(t *testing.T) {
	if got := New("x").Name(); got != "npm" {
		t.Errorf("Name() = %q, want %q", got, "npm")
	}
}
