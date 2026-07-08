package cmd

import (
	"fmt"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
	"github.com/achyuta0001/tripwyre/internal/reporter"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Scan for config drift between expected and observed state",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// TODO: implement config scanner
		// s := configscanner.New(cfg.Config)
		// findings, err := s.Scan()

		_ = cfg
		var findings []finding.Finding

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
	rootCmd.AddCommand(configCmd)
}
