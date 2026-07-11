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
func runScan(w io.Writer, build func(*config.Config) []scanner.Scanner) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var findings []finding.Finding
	for _, s := range build(cfg) {
		fs, err := s.Scan()
		if err != nil {
			return fmt.Errorf("%s scanner: %w", s.Name(), err)
		}
		findings = append(findings, fs...)
	}

	r, err := selectReporter(format)
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

func selectReporter(format string) (reporter.Synthesizer, error) {
	switch format {
	case "", "text":
		return reporter.NewTemplateReporter(), nil
	case "json":
		return reporter.NewJSONReporter(), nil
	default:
		return nil, fmt.Errorf("invalid --format value: %q (use text or json)", format)
	}
}
