package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
	"github.com/ahmedfawzy/devops-toolkit/pkg/notify"
	"github.com/ahmedfawzy/devops-toolkit/pkg/reporter"
	"github.com/spf13/cobra"
)

var (
	awsRegions     string
	outputFormat   string
	includeEC2     bool
	includeEBS     bool
	includeSnaps   bool
	includeEIPs    bool
	includeRDS     bool
	slackWebhook   string
	alertThreshold float64
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "AWS resource auditing and optimization",
	Long:  "Audit AWS resources to identify waste and optimization opportunities",
}

var awsAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit AWS resources for waste",
	Long: `Scan your AWS account for wasteful resources:

- Unattached EBS volumes
- Underutilized EC2 instances (< 5% CPU)
- Orphaned EBS snapshots
- Unused Elastic IPs

Example:
  dtk aws audit --regions us-east-1
  dtk aws audit --regions us-east-1,us-west-2,eu-west-1
  dtk aws audit --regions eu-west-1 --format json`,
	RunE: runAWSAudit,
}

func init() {
	rootCmd.AddCommand(awsCmd)
	awsCmd.AddCommand(awsAuditCmd)

	awsAuditCmd.Flags().StringVarP(&awsRegions, "regions", "r", "", "Comma-separated AWS regions (e.g., us-east-1,us-west-2,eu-west-1)")
	awsAuditCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, csv")
	awsAuditCmd.Flags().BoolVar(&includeEC2, "ec2", true, "Include EC2 instance analysis")
	awsAuditCmd.Flags().BoolVar(&includeEBS, "ebs", true, "Include EBS volume analysis")
	awsAuditCmd.Flags().BoolVar(&includeSnaps, "snapshots", true, "Include snapshot analysis")
	awsAuditCmd.Flags().BoolVar(&includeEIPs, "eips", true, "Include Elastic IP analysis")
	awsAuditCmd.Flags().BoolVar(&includeRDS, "rds", true, "Include RDS instance analysis")
	awsAuditCmd.Flags().StringVar(&slackWebhook, "slack-webhook", "", "Slack webhook URL for sending alerts")
	awsAuditCmd.Flags().Float64Var(&alertThreshold, "alert-threshold", 0, "Minimum savings threshold to trigger Slack alert (default 0)")
}

func runAWSAudit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse regions from comma-separated string
	var regions []string
	if awsRegions == "" {
		// Use environment variable if regions not specified
		awsRegions = os.Getenv("AWS_REGION")
		if awsRegions == "" {
			awsRegions = "us-east-1"
		}
	}

	// Split on comma and trim whitespace from each region
	for _, region := range strings.Split(awsRegions, ",") {
		trimmed := strings.TrimSpace(region)
		if trimmed != "" {
			regions = append(regions, trimmed)
		}
	}

	// Display all regions being scanned
	fmt.Printf("🔍 Auditing AWS resources in regions: %s\n", strings.Join(regions, ", "))

	// Aggregate results across all regions
	allResults := &aws.AuditResults{}

	// Process each region
	for _, region := range regions {
		fmt.Printf("\n═══ Region: %s ═══\n\n", region)

		auditor, err := aws.NewAuditor(ctx, region)
		if err != nil {
			return fmt.Errorf("failed to create AWS auditor for region %s: %w", region, err)
		}

		// Audit EBS volumes
		if includeEBS {
			fmt.Println("📦 Checking EBS volumes...")
			volumes, err := auditor.FindUnattachedVolumes(ctx)
			if err != nil {
				return fmt.Errorf("failed to audit EBS volumes in %s: %w", region, err)
			}
			allResults.UnattachedVolumes = append(allResults.UnattachedVolumes, volumes...)
		}

		// Audit EC2 instances
		if includeEC2 {
			fmt.Println("💻 Checking EC2 instances...")
			instances, err := auditor.FindUnderutilizedInstances(ctx)
			if err != nil {
				return fmt.Errorf("failed to audit EC2 instances in %s: %w", region, err)
			}
			allResults.UnderutilizedInstances = append(allResults.UnderutilizedInstances, instances...)
		}

		// Audit snapshots
		if includeSnaps {
			fmt.Println("📸 Checking EBS snapshots...")
			snapshots, err := auditor.FindOrphanedSnapshots(ctx)
			if err != nil {
				return fmt.Errorf("failed to audit snapshots in %s: %w", region, err)
			}
			allResults.OrphanedSnapshots = append(allResults.OrphanedSnapshots, snapshots...)
		}

		// Audit Elastic IPs
		if includeEIPs {
			fmt.Println("🌐 Checking Elastic IPs...")
			eips, err := auditor.FindUnusedElasticIPs(ctx)
			if err != nil {
				return fmt.Errorf("failed to audit Elastic IPs in %s: %w", region, err)
			}
			allResults.UnusedElasticIPs = append(allResults.UnusedElasticIPs, eips...)
		}

		// Audit RDS instances
		if includeRDS {
			fmt.Println("🗄️  Checking RDS instances...")
			rdsInstances, err := auditor.FindUnderutilizedRDS(ctx)
			if err != nil {
				return fmt.Errorf("failed to audit RDS instances in %s: %w", region, err)
			}
			allResults.UnderutilizedRDSInstances = append(allResults.UnderutilizedRDSInstances, rdsInstances...)
		}
	}

	// Calculate combined total savings across all regions
	allResults.CalculateSavings()

	fmt.Println()

	// Output aggregated results
	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderAuditResults(allResults); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	// Send Slack alert if configured and threshold met
	if slackWebhook != "" && allResults.TotalPotentialSavings > alertThreshold {
		fmt.Println("\n📢 Sending Slack alert...")

		notifier := notify.NewSlackNotifier(slackWebhook)

		// Build alert message
		message := fmt.Sprintf("AWS audit completed for regions: %s", strings.Join(regions, ", "))

		err := notifier.SendAlert(message, *allResults)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to send Slack alert: %v\n", err)
			// Don't fail the whole command if Slack alert fails
		} else {
			fmt.Println("✅ Slack alert sent successfully!")
		}
	} else if slackWebhook != "" {
		fmt.Printf("\nℹ️  Slack webhook configured but savings ($%.2f) below threshold ($%.2f) - no alert sent\n",
			allResults.TotalPotentialSavings, alertThreshold)
	}

	return nil
}
