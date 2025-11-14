package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
	"github.com/ahmedfawzy/devops-toolkit/pkg/reporter"
	"github.com/spf13/cobra"
)

var (
	days       int
	groupBy    string
	topN       int
	costRegion string
)

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "AWS cost reporting and analysis",
	Long:  "Generate cost reports and identify spending trends",
}

var costReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate AWS cost report",
	Long: `Generate detailed AWS cost report with spending breakdown:

- Daily/weekly/monthly spending trends
- Cost by service (EC2, S3, RDS, etc.)
- Top spending resources
- Month-over-month comparison

Example:
  dtk cost report --days 7
  dtk cost report --days 30 --group-by SERVICE
  dtk cost report --days 90 --format json`,
	RunE: runCostReport,
}

func init() {
	rootCmd.AddCommand(costCmd)
	costCmd.AddCommand(costReportCmd)

	costReportCmd.Flags().IntVarP(&days, "days", "d", 7, "Number of days to analyze")
	costReportCmd.Flags().StringVarP(&groupBy, "group-by", "g", "SERVICE", "Group by: SERVICE, REGION, INSTANCE_TYPE")
	costReportCmd.Flags().IntVarP(&topN, "top", "t", 10, "Show top N spending items")
	costReportCmd.Flags().StringVarP(&costRegion, "region", "r", "", "AWS region")
	costReportCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
}

func runCostReport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if costRegion == "" {
		costRegion = os.Getenv("AWS_REGION")
		if costRegion == "" {
			costRegion = "us-east-1"
		}
	}

	fmt.Printf("💰 Generating cost report for last %d days...\n\n", days)

	analyzer, err := aws.NewCostAnalyzer(ctx, costRegion)
	if err != nil {
		return fmt.Errorf("failed to create cost analyzer: %w", err)
	}

	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days)

	fmt.Printf("📅 Period: %s to %s\n", startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))
	fmt.Printf("🏷️  Grouping: %s\n\n", groupBy)

	results, err := analyzer.GetCostAndUsage(ctx, startDate, endDate, groupBy)
	if err != nil {
		return fmt.Errorf("failed to get cost data: %w", err)
	}

	// Limit to top N items
	results.LimitToTopN(topN)

	// Output results
	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderCostResults(results); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}
