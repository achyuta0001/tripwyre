package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
	"github.com/achyuta0001/tripwyre/internal/scanner"
	"github.com/achyuta0001/tripwyre/internal/scanner/deps"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all scanners and print a unified report",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(os.Stdout, func(cfg *config.Config) []scanner.Scanner {
			// TODO: add config and log scanners as they are implemented
			return []scanner.Scanner{
				deps.New(cfg.Deps, "."),
			}
		})
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func checkFailOn(findings []finding.Finding, threshold string) error {
	if threshold == "" {
		return nil
	}

	sev := finding.Severity(strings.ToUpper(threshold))
	order := map[finding.Severity]int{
		finding.Info:     0,
		finding.Warning:  1,
		finding.Critical: 2,
	}

	thresholdLevel, ok := order[sev]
	if !ok {
		return fmt.Errorf("invalid --fail-on value: %q (use critical, warning, or info)", threshold)
	}

	var hits int
	for _, f := range findings {
		if order[f.Severity] >= thresholdLevel {
			hits++
		}
	}

	if hits > 0 {
		return fmt.Errorf("%d finding(s) at or above %s severity", hits, strings.ToLower(threshold))
	}

	return nil
}
