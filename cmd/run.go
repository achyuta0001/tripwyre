package cmd

import (
	"fmt"
	"io"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
	"github.com/achyuta0001/tripwyre/internal/reporter"
	"github.com/achyuta0001/tripwyre/internal/scanner"
)

// runScan is the shared pipeline behind every subcommand:
// load config → run scanners → report → apply --fail-on.
// build receives the loaded config and returns the scanners to run,
// so each subcommand only decides which scanners it wires in.
func runScan(w io.Writer, build func(*config.Config) ([]scanner.Scanner, error)) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	scanners, err := build(cfg)
	if err != nil {
		return err
	}

	var findings []finding.Finding
	for _, s := range scanners {
		fs, err := s.Scan()
		if err != nil {
			return fmt.Errorf("%s scanner: %w", s.Name(), err)
		}
		findings = append(findings, fs...)
	}

	r, err := selectReporter(cfg, format)
	if err != nil {
		return err
	}
	output, err := r.Summarize(findings)
	if err != nil {
		return err
	}
	fmt.Fprint(w, output)

	return checkFailOn(findings, failOn)
}

// selectReporter picks the output backend. --format=json always wins
// (machine-readable output must stay deterministic); otherwise the
// [reporter] backend from tripwyre.toml decides between the free template
// report and the opt-in LLM synthesis.
func selectReporter(cfg *config.Config, format string) (reporter.Synthesizer, error) {
	switch format {
	case "", "text":
		if cfg.Reporter.Backend == "llm" {
			return reporter.NewLLMReporter(cfg.Reporter)
		}
		return reporter.NewTemplateReporter(), nil
	case "json":
		return reporter.NewJSONReporter(), nil
	default:
		return nil, fmt.Errorf("invalid --format value: %q (use text or json)", format)
	}
}
