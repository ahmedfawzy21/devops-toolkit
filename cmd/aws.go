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

	// Security command flags
	securityRegion       string
	securitySlackWebhook string
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

var awsSecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Audit AWS security configuration",
	Long: `Scan your AWS account for security issues:

- Public S3 buckets
- Security groups with risky ports (22, 3389, 3306, 5432, 27017) exposed to 0.0.0.0/0

Example:
  dtk aws security --region us-east-1
  dtk aws security --region eu-west-1 --slack-webhook https://hooks.slack.com/...`,
	RunE: runAWSSecurity,
}

func init() {
	rootCmd.AddCommand(awsCmd)
	awsCmd.AddCommand(awsAuditCmd)
	awsCmd.AddCommand(awsSecurityCmd)

	awsAuditCmd.Flags().StringVarP(&awsRegions, "regions", "r", "", "Comma-separated AWS regions (e.g., us-east-1,us-west-2,eu-west-1)")
	awsAuditCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, csv")
	awsAuditCmd.Flags().BoolVar(&includeEC2, "ec2", true, "Include EC2 instance analysis")
	awsAuditCmd.Flags().BoolVar(&includeEBS, "ebs", true, "Include EBS volume analysis")
	awsAuditCmd.Flags().BoolVar(&includeSnaps, "snapshots", true, "Include snapshot analysis")
	awsAuditCmd.Flags().BoolVar(&includeEIPs, "eips", true, "Include Elastic IP analysis")
	awsAuditCmd.Flags().BoolVar(&includeRDS, "rds", true, "Include RDS instance analysis")
	awsAuditCmd.Flags().StringVar(&slackWebhook, "slack-webhook", "", "Slack webhook URL for sending alerts")
	awsAuditCmd.Flags().Float64Var(&alertThreshold, "alert-threshold", 0, "Minimum savings threshold to trigger Slack alert (default 0)")

	// Security command flags
	awsSecurityCmd.Flags().StringVarP(&securityRegion, "region", "r", "", "AWS region to audit (e.g., us-east-1)")
	awsSecurityCmd.Flags().StringVar(&securitySlackWebhook, "slack-webhook", "", "Slack webhook URL for sending security alerts")
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

func runAWSSecurity(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Determine region
	region := securityRegion
	if region == "" {
		region = os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
	}

	fmt.Println()
	fmt.Println("\033[1m🔒 AWS Security Audit\033[0m")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("Region: %s\n\n", region)

	auditor, err := aws.NewSecurityAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create security auditor: %w", err)
	}

	results := &aws.SecurityResults{}

	// Check S3 buckets
	fmt.Println("🪣 \033[1mPublic S3 Buckets\033[0m")
	fmt.Println("─────────────────────────────────────────────────────────────")

	publicBuckets, err := auditor.CheckPublicS3Buckets(ctx)
	if err != nil {
		fmt.Printf("  ⚠️  Warning: Failed to check S3 buckets: %v\n", err)
	} else {
		results.PublicS3Buckets = publicBuckets
		if len(publicBuckets) == 0 {
			fmt.Println("  No public buckets found ✅")
		} else {
			for _, bucket := range publicBuckets {
				color := aws.GetSeverityColor(bucket.Severity)
				reset := aws.ResetSecurityColor()
				fmt.Printf("  %s• %s (%s) - %s%s\n", color, bucket.BucketName, bucket.PublicAccess, severityLabel(bucket.Severity), reset)
			}
		}
	}

	fmt.Println()

	// Check Security Groups
	fmt.Println("🛡️ \033[1mOpen Security Groups (risky ports exposed to 0.0.0.0/0)\033[0m")
	fmt.Println("─────────────────────────────────────────────────────────────")

	openSGs, err := auditor.CheckOpenSecurityGroups(ctx)
	if err != nil {
		fmt.Printf("  ⚠️  Warning: Failed to check security groups: %v\n", err)
	} else {
		results.OpenSecurityGroups = openSGs
		if len(openSGs) == 0 {
			fmt.Println("  No risky security groups found ✅")
		} else {
			// Print table header
			fmt.Printf("%-25s | %-5s | %-8s | %-10s | %s\n",
				"SECURITY GROUP", "PORT", "PROTOCOL", "SOURCE", "SEVERITY")
			fmt.Println("─────────────────────────┼───────┼──────────┼────────────┼──────────")

			for _, sg := range openSGs {
				color := aws.GetSeverityColor(sg.Severity)
				reset := aws.ResetSecurityColor()
				sgDisplay := fmt.Sprintf("%s (%s)", sg.GroupID, truncateString(sg.GroupName, 10))
				fmt.Printf("%s%-25s | %-5d | %-8s | %-10s | %s%s\n",
					color,
					truncateString(sgDisplay, 25),
					sg.Port,
					sg.Protocol,
					sg.Source,
					severityLabel(sg.Severity),
					reset)
			}
		}
	}

	fmt.Println()

	// Summary
	counts := results.CountBySeverity()
	fmt.Println("\033[1mSummary:\033[0m")
	fmt.Printf("🔴 Critical: %d\n", counts[aws.SeverityCritical])
	fmt.Printf("🟡 High: %d\n", counts[aws.SeverityHigh])
	fmt.Printf("🟠 Medium: %d\n", counts[aws.SeverityMedium])

	// Send Slack alert if configured and findings exist
	totalFindings := counts[aws.SeverityCritical] + counts[aws.SeverityHigh] + counts[aws.SeverityMedium]
	if securitySlackWebhook != "" && totalFindings > 0 {
		fmt.Println("\n📢 Sending Slack alert...")

		notifier := notify.NewSlackNotifier(securitySlackWebhook)
		slackMsg := buildSecuritySlackMessage(region, results)

		err := notifier.SendSlackMessage(slackMsg)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to send Slack alert: %v\n", err)
		} else {
			fmt.Println("✅ Slack alert sent successfully!")
		}
	} else if securitySlackWebhook != "" && totalFindings == 0 {
		fmt.Println("\nℹ️  Slack webhook configured but no security findings - no alert sent")
	}

	return nil
}

func severityLabel(severity aws.Severity) string {
	switch severity {
	case aws.SeverityCritical:
		return "🔴 CRITICAL"
	case aws.SeverityHigh:
		return "🟡 HIGH"
	case aws.SeverityMedium:
		return "🟠 MEDIUM"
	default:
		return string(severity)
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func buildSecuritySlackMessage(region string, results *aws.SecurityResults) notify.SlackMessage {
	counts := results.CountBySeverity()

	// Determine color based on findings
	color := "good"
	if counts[aws.SeverityHigh] > 0 || counts[aws.SeverityMedium] > 0 {
		color = "warning"
	}
	if counts[aws.SeverityCritical] > 0 {
		color = "danger"
	}

	// Build findings text
	var findingsText string

	if len(results.PublicS3Buckets) > 0 {
		findingsText += fmt.Sprintf(":bucket: *Public S3 Buckets:* %d\n", len(results.PublicS3Buckets))
		for _, bucket := range results.PublicS3Buckets {
			findingsText += fmt.Sprintf("  • `%s` (%s)\n", bucket.BucketName, bucket.PublicAccess)
		}
	}

	if len(results.OpenSecurityGroups) > 0 {
		findingsText += fmt.Sprintf(":shield: *Open Security Groups:* %d\n", len(results.OpenSecurityGroups))
		for _, sg := range results.OpenSecurityGroups {
			portName := aws.RiskyPorts[sg.Port]
			findingsText += fmt.Sprintf("  • `%s` - Port %d (%s) open to %s\n",
				sg.GroupID, sg.Port, portName, sg.Source)
		}
	}

	if findingsText == "" {
		findingsText = ":white_check_mark: No security issues found!"
	}

	return notify.SlackMessage{
		Text: fmt.Sprintf(":lock: *AWS Security Audit Report*\nRegion: %s", region),
		Attachments: []notify.Attachment{
			{
				Color: color,
				Text:  findingsText,
				Fields: []notify.Field{
					{
						Title: ":red_circle: Critical",
						Value: fmt.Sprintf("%d", counts[aws.SeverityCritical]),
						Short: true,
					},
					{
						Title: ":large_yellow_circle: High",
						Value: fmt.Sprintf("%d", counts[aws.SeverityHigh]),
						Short: true,
					},
				},
			},
		},
	}
}
