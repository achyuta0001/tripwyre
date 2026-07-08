package cmd

import (
	"fmt"
	"os"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
	"github.com/achyuta0001/tripwyre/internal/reporter"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all scanners and print a unified report",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// TODO: wire up real scanners as they are implemented
		// scanners := []scanner.Scanner{
		//     deps.New(cfg.Deps),
		//     configscanner.New(cfg.Config),
		//     logs.New(cfg.Logs),
		// }

		var findings []finding.Finding

		// placeholder until scanners are implemented
		_ = cfg

		r := reporter.NewTemplateReporter()
		output, err := r.Summarize(findings)
		if err != nil {
			return err
		}

		fmt.Print(output)

		return checkFailOn(findings, failOn)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func checkFailOn(findings []finding.Finding, threshold string) error {
	if threshold == "" {
		return nil
	}

	sev := finding.Severity(threshold)
	order := map[finding.Severity]int{
		finding.Info:     0,
		finding.Warning:  1,
		finding.Critical: 2,
	}

	thresholdLevel, ok := order[sev]
	if !ok {
		return fmt.Errorf("invalid --fail-on value: %q (use critical, warning, or info)", threshold)
	}

	for _, f := range findings {
		if order[f.Severity] >= thresholdLevel {
			os.Exit(1)
		}
	}

	return nil
}
