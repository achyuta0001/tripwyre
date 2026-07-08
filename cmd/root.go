package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	failOn   string
)

var rootCmd = &cobra.Command{
	Use:   "tripwyre",
	Short: "Unified project intelligence — deps, config, and log scanning",
	Long: `tripwyre scans your project for dependency risks, config drift, and log anomalies.
Runs locally, requires no cloud, and costs nothing by default.

Add your own LLM API key to enable cross-scanner synthesis.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "tripwyre.toml", "config file")
	rootCmd.PersistentFlags().StringVar(&failOn, "fail-on", "", "exit non-zero if findings at this severity or above exist (critical|warning|info)")
}
