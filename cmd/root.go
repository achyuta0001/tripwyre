package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is stamped at release time via:
//
//	go build -ldflags "-X github.com/achyuta0001/tripwyre/cmd.version=v1.2.3"
var version = "dev"

var (
	cfgFile string
	failOn  string
	format  string
)

var rootCmd = &cobra.Command{
	Use:   "tripwyre",
	Short: "Unified project intelligence — deps, config, and log scanning",
	Long: `tripwyre scans your project for dependency risks, config drift, and log anomalies.
Runs locally, requires no cloud, and costs nothing by default.

Add your own LLM API key to enable cross-scanner synthesis.`,
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
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
	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "output format (text|json)")
}
