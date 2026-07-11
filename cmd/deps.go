package cmd

import (
	"os"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/scanner"
	"github.com/achyuta0001/tripwyre/internal/scanner/deps"
	"github.com/spf13/cobra"
)

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Scan dependencies for CVEs, license issues, and staleness",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(os.Stdout, func(cfg *config.Config) ([]scanner.Scanner, error) {
			return []scanner.Scanner{deps.New(cfg.Deps, ".")}, nil
		})
	},
}

func init() {
	rootCmd.AddCommand(depsCmd)
}
