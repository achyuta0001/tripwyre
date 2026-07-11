package cmd

import (
	"os"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/scanner"
	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Scan logs for error spikes, anomalies, and recurring patterns",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(os.Stdout, func(cfg *config.Config) ([]scanner.Scanner, error) {
			// TODO: implement log scanner
			// return []scanner.Scanner{logs.New(cfg.Logs)}, nil
			return nil, nil
		})
	},
}

func init() {
	rootCmd.AddCommand(logsCmd)
}
