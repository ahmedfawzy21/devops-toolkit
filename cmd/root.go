package cmd

import (
	"fmt"


	"github.com/spf13/cobra"
)

var (
	// Version information
	Version   = "1.0.0"
	BuildDate = "2025-11-14"
)

var rootCmd = &cobra.Command{
	Use:   "dtk",
	Short: "DevOps Toolkit - Essential tools for DevOps engineers",
	Long: `dtk (DevOps Toolkit) provides essential utilities for DevOps engineers:
	
- AWS resource auditing and cost optimization
- Kubernetes cluster health checking
- Cost reporting and analysis

Built with ❤️ for DevOps engineers by Ahmed Fawzy`,
	Version: Version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	
	// Add version template
	rootCmd.SetVersionTemplate(fmt.Sprintf("dtk version %s (built: %s)\n", Version, BuildDate))
}
