package cmd

import (
	"os"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/scanner"
	"github.com/achyuta0001/tripwyre/internal/scanner/configscan"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Scan for config drift between expected and observed state",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(os.Stdout, func(cfg *config.Config) ([]scanner.Scanner, error) {
			cs, err := configscan.New(cfg.Config, ".")
			if err != nil {
				return nil, err
			}
			return []scanner.Scanner{cs}, nil
		})
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
