package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// all supported ecosystems by default: missing lockfiles are skipped,
	// so this makes zero-config scans work in any project type
	if got := cfg.Deps.Ecosystems; len(got) != 3 || got[0] != "npm" || got[1] != "pip" || got[2] != "cargo" {
		t.Errorf("Deps.Ecosystems = %v, want [npm pip cargo]", got)
	}
	// staleness is opt-in: it costs one registry request per package
	if cfg.Deps.StalenessDays != 0 {
		t.Errorf("Deps.StalenessDays = %d, want 0 (disabled by default)", cfg.Deps.StalenessDays)
	}
	if cfg.Logs.ErrorSpikeThreshold != 20 {
		t.Errorf("Logs.ErrorSpikeThreshold = %d, want 20", cfg.Logs.ErrorSpikeThreshold)
	}
	if cfg.Reporter.Backend != "template" {
		t.Errorf("Reporter.Backend = %q, want %q", cfg.Reporter.Backend, "template")
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tripwyre.toml")
	content := `
[deps]
ecosystems = ["pip", "cargo"]
staleness_days = 90

[reporter]
backend = "llm"
model = "claude-haiku-4-5-20251001"
api_key_env = "ANTHROPIC_API_KEY"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := cfg.Deps.Ecosystems; len(got) != 2 || got[0] != "pip" || got[1] != "cargo" {
		t.Errorf("Deps.Ecosystems = %v, want [pip cargo]", got)
	}
	if cfg.Deps.StalenessDays != 90 {
		t.Errorf("Deps.StalenessDays = %d, want 90", cfg.Deps.StalenessDays)
	}
	if cfg.Reporter.Backend != "llm" {
		t.Errorf("Reporter.Backend = %q, want %q", cfg.Reporter.Backend, "llm")
	}
	// sections absent from the file keep their defaults
	if cfg.Logs.ErrorSpikeThreshold != 20 {
		t.Errorf("Logs.ErrorSpikeThreshold = %d, want default 20", cfg.Logs.ErrorSpikeThreshold)
	}
}

func TestLoadInvalidTOMLErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tripwyre.toml")
	if err := os.WriteFile(path, []byte("[deps\nnot toml"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want parse error for invalid TOML")
	}
}
