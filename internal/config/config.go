package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Deps     DepsConfig     `toml:"deps"`
	Config   ConfigConfig   `toml:"config"`
	Logs     LogsConfig     `toml:"logs"`
	Reporter ReporterConfig `toml:"reporter"`
}

type DepsConfig struct {
	Ecosystems       []string `toml:"ecosystems"`
	LicenseAllowlist []string `toml:"license_allowlist"`
	StalenessDays    int      `toml:"staleness_days"`
}

type ConfigConfig struct {
	Sources        []string `toml:"sources"`
	Expected       string   `toml:"expected"`
	RedactPatterns []string `toml:"redact_patterns"`
}

type LogsConfig struct {
	Sources             []string `toml:"sources"`
	ErrorSpikeThreshold int      `toml:"error_spike_threshold"`
	ClusterMinSize      int      `toml:"cluster_min_size"`
}

type ReporterConfig struct {
	Backend   string `toml:"backend"` // "template" or "llm"
	Model     string `toml:"model"`
	APIKeyEnv string `toml:"api_key_env"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Deps: DepsConfig{
			Ecosystems:       []string{"npm"},
			LicenseAllowlist: []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"},
			StalenessDays:    365,
		},
		Logs: LogsConfig{
			ErrorSpikeThreshold: 20,
			ClusterMinSize:      5,
		},
		Reporter: ReporterConfig{
			Backend: "template",
		},
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
