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

var costLogGroupsCmd = &cobra.Command{
	Use:   "loggroups",
	Short: "Find wasteful CloudWatch log groups",
	Long: `Scan CloudWatch Logs for cost optimization opportunities:

- Log groups with no retention policy (stored indefinitely)
- Dead log groups with no incoming events in the last 30 days

Example:
  dtk cost loggroups --region us-east-1
  dtk cost loggroups --region eu-west-1 --format json`,
	RunE: runCostLogGroups,
}

var costDynamoDBCmd = &cobra.Command{
	Use:   "dynamodb",
	Short: "Find DynamoDB waste and risk",
	Long: `Scan DynamoDB tables for cost and resilience issues:

- Tables without Point-in-Time Recovery (PITR) enabled
- Overprovisioned provisioned-capacity tables (< 20% utilization)

Example:
  dtk cost dynamodb --region us-east-1
  dtk cost dynamodb --region eu-west-1 --format json`,
	RunE: runCostDynamoDB,
}

var costSavingsCmd = &cobra.Command{
	Use:   "savings",
	Short: "Show Reserved Instance and Savings Plan recommendations",
	Long: `Fetch AWS Cost Explorer purchase recommendations:

- Reserved Instance recommendations (EC2 Compute, 1yr, No Upfront)
- Compute Savings Plan recommendations (1yr, No Upfront)

Requires 30+ days of usage history before AWS can generate recommendations.

Example:
  dtk cost savings --region us-east-1
  dtk cost savings --region us-east-1 --format json`,
	RunE: runCostSavings,
}

func init() {
	rootCmd.AddCommand(costCmd)
	costCmd.AddCommand(costReportCmd)
	costCmd.AddCommand(costLogGroupsCmd)
	costCmd.AddCommand(costDynamoDBCmd)
	costCmd.AddCommand(costSavingsCmd)

	costReportCmd.Flags().IntVarP(&days, "days", "d", 7, "Number of days to analyze")
	costReportCmd.Flags().StringVarP(&groupBy, "group-by", "g", "SERVICE", "Group by: SERVICE, REGION, INSTANCE_TYPE")
	costReportCmd.Flags().IntVarP(&topN, "top", "t", 10, "Show top N spending items")
	costReportCmd.Flags().StringVarP(&costRegion, "region", "r", "", "AWS region")
	costReportCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	costLogGroupsCmd.Flags().StringVarP(&costRegion, "region", "r", "", "AWS region")
	costLogGroupsCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	costDynamoDBCmd.Flags().StringVarP(&costRegion, "region", "r", "", "AWS region")
	costDynamoDBCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	costSavingsCmd.Flags().StringVarP(&costRegion, "region", "r", "", "AWS region")
	costSavingsCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
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

func resolveCostRegion() string {
	if costRegion != "" {
		return costRegion
	}
	if region := os.Getenv("AWS_REGION"); region != "" {
		return region
	}
	return "us-east-1"
}

func runCostLogGroups(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveCostRegion()

	fmt.Printf("🔍 Scanning CloudWatch log groups in %s...\n\n", region)

	auditor, err := aws.NewCloudWatchAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create CloudWatch auditor: %w", err)
	}

	withoutRetention, err := auditor.FindLogGroupsWithoutRetention(ctx)
	if err != nil {
		return fmt.Errorf("failed to find log groups without retention: %w", err)
	}

	dead, err := auditor.FindDeadLogGroups(ctx)
	if err != nil {
		return fmt.Errorf("failed to find dead log groups: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderLogGroupResults(withoutRetention, dead); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runCostDynamoDB(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveCostRegion()

	fmt.Printf("🔍 Scanning DynamoDB tables in %s...\n\n", region)

	auditor, err := aws.NewDynamoDBAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create DynamoDB auditor: %w", err)
	}

	withoutPITR, err := auditor.FindTablesWithoutPITR(ctx)
	if err != nil {
		return fmt.Errorf("failed to find tables without PITR: %w", err)
	}

	overprovisioned, err := auditor.FindOverprovisionedTables(ctx)
	if err != nil {
		return fmt.Errorf("failed to find overprovisioned tables: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderDynamoDBResults(withoutPITR, overprovisioned); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runCostSavings(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveCostRegion()

	fmt.Printf("🔍 Fetching savings recommendations in %s...\n\n", region)

	analyzer, err := aws.NewSavingsAnalyzer(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create savings analyzer: %w", err)
	}

	reservations, err := analyzer.GetReservationRecommendations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get reservation recommendations: %w", err)
	}

	savingsPlans, err := analyzer.GetSavingsPlanRecommendations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get savings plan recommendations: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderSavingsResults(reservations, savingsPlans); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}
