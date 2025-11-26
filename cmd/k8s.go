package cmd

import (
	"context"
	"fmt"

	"github.com/ahmedfawzy/devops-toolkit/pkg/k8s"
	"github.com/ahmedfawzy/devops-toolkit/pkg/notify"
	"github.com/ahmedfawzy/devops-toolkit/pkg/reporter"
	"github.com/spf13/cobra"
)

var (
	namespace         string
	allNamespaces     bool
	checkNodes        bool
	expiryDays        int
	k8sSlackWebhook   string
)

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Kubernetes cluster operations",
	Long:  "Health checks and diagnostics for Kubernetes clusters",
}

var k8sHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check Kubernetes cluster health",
	Long: `Perform comprehensive health check on your Kubernetes cluster:

- Pod status across namespaces
- Failed deployments and statefulsets
- Resource usage and limits
- Node status and capacity
- Recent warning events

Example:
  dtk k8s health
  dtk k8s health --namespace default
  dtk k8s health --all-namespaces
  dtk k8s health --format json`,
	RunE: runK8sHealth,
}

var k8sCertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Check TLS certificate expiry in Kubernetes",
	Long: `Scan Kubernetes secrets for TLS certificates and check expiry dates:

- Find kubernetes.io/tls secrets
- Parse certificates and extract expiry information
- Alert on certificates expiring soon
- Color-coded output: red (<7 days), yellow (<30 days), green (>30 days)

Example:
  dtk k8s certs
  dtk k8s certs --namespace default
  dtk k8s certs --expiry-days 60
  dtk k8s certs --slack-webhook https://hooks.slack.com/xxx`,
	RunE: runK8sCerts,
}

var k8sPDBCmd = &cobra.Command{
	Use:   "pdb",
	Short: "Check PodDisruptionBudget status",
	Long: `Check PodDisruptionBudget (PDB) health across your Kubernetes cluster:

- Identify PDBs with zero disruptions allowed
- Detect misconfigured PDBs with no matching pods
- Find PDBs with unhealthy pods
- Color-coded output: red (critical), yellow (at-risk), green (healthy)

Example:
  dtk k8s pdb
  dtk k8s pdb --namespace production
  dtk k8s pdb --slack-webhook https://hooks.slack.com/xxx`,
	RunE: runK8sPDB,
}

func init() {
	rootCmd.AddCommand(k8sCmd)
	k8sCmd.AddCommand(k8sHealthCmd)
	k8sCmd.AddCommand(k8sCertsCmd)
	k8sCmd.AddCommand(k8sPDBCmd)

	k8sHealthCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace (default: all namespaces)")
	k8sHealthCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", true, "Check all namespaces")
	k8sHealthCmd.Flags().BoolVar(&checkNodes, "nodes", true, "Include node health check")
	k8sHealthCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	k8sCertsCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace (default: all namespaces)")
	k8sCertsCmd.Flags().IntVar(&expiryDays, "expiry-days", 30, "Show certificates expiring within N days")
	k8sCertsCmd.Flags().StringVar(&k8sSlackWebhook, "slack-webhook", "", "Slack webhook URL for certificate expiry alerts")

	k8sPDBCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace (default: all namespaces)")
	k8sPDBCmd.Flags().StringVar(&k8sSlackWebhook, "slack-webhook", "", "Slack webhook URL for PDB alerts")
}

func runK8sHealth(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	fmt.Println("🏥 Checking Kubernetes cluster health...\n")

	checker, err := k8s.NewHealthChecker()
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	results := &k8s.HealthResults{}

	// Check pod health
	fmt.Println("🔍 Checking pods...")
	ns := namespace
	if allNamespaces {
		ns = ""
	}
	
	podHealth, err := checker.CheckPods(ctx, ns)
	if err != nil {
		return fmt.Errorf("failed to check pods: %w", err)
	}
	results.Pods = podHealth

	// Check deployments
	fmt.Println("📦 Checking deployments...")
	deployments, err := checker.CheckDeployments(ctx, ns)
	if err != nil {
		return fmt.Errorf("failed to check deployments: %w", err)
	}
	results.Deployments = deployments

	// Check nodes
	if checkNodes {
		fmt.Println("🖥️  Checking nodes...")
		nodes, err := checker.CheckNodes(ctx)
		if err != nil {
			return fmt.Errorf("failed to check nodes: %w", err)
		}
		results.Nodes = nodes
	}

	// Check recent events
	fmt.Println("📋 Checking recent events...")
	events, err := checker.GetRecentWarningEvents(ctx, ns)
	if err != nil {
		return fmt.Errorf("failed to check events: %w", err)
	}
	results.WarningEvents = events

	fmt.Println()

	// Output results
	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderHealthResults(results); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runK8sCerts(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	fmt.Println("🔐 Checking TLS certificate expiry in Kubernetes...\n")

	checker, err := k8s.NewHealthChecker()
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Determine namespace
	ns := namespace
	if ns == "" {
		ns = "" // Empty string means all namespaces
		fmt.Printf("Scanning all namespaces for TLS certificates expiring within %d days...\n\n", expiryDays)
	} else {
		fmt.Printf("Scanning namespace '%s' for TLS certificates expiring within %d days...\n\n", ns, expiryDays)
	}

	// Check certificate expiry
	results, err := checker.CheckCertificateExpiry(ctx, ns, expiryDays)
	if err != nil {
		return fmt.Errorf("failed to check certificates: %w", err)
	}

	// Display results with color coding
	if len(results.Certificates) == 0 {
		fmt.Printf("✅ No certificates expiring within %d days (scanned %d TLS secrets)\n",
			expiryDays, results.TotalScanned)
	} else {
		fmt.Printf("Found %d certificate(s) expiring within %d days (scanned %d TLS secrets)\n\n",
			len(results.Certificates), expiryDays, results.TotalScanned)

		// Print header
		fmt.Printf("%-30s %-20s %-15s %-40s %-20s %s\n",
			"SECRET", "NAMESPACE", "DAYS REMAINING", "DNS NAMES", "EXPIRY DATE", "STATUS")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")

		// Print each certificate with color coding
		for _, cert := range results.Certificates {
			color := cert.GetColorCode()
			reset := k8s.ResetColor()

			// Truncate secret name if too long
			secretName := cert.SecretName
			if len(secretName) > 28 {
				secretName = secretName[:25] + "..."
			}

			// Truncate namespace if too long
			ns := cert.Namespace
			if len(ns) > 18 {
				ns = ns[:15] + "..."
			}

			dnsNames := cert.FormatDNSNames()
			if len(dnsNames) > 38 {
				dnsNames = dnsNames[:35] + "..."
			}

			expiryStr := cert.ExpiryDate.Format("2006-01-02 15:04")

			fmt.Printf("%s%-30s %-20s %-15d %-40s %-20s %s%s\n",
				color,
				secretName,
				ns,
				cert.DaysRemaining,
				dnsNames,
				expiryStr,
				cert.Status,
				reset)
		}

		// Print summary
		fmt.Println()
		if results.ExpiredCount > 0 {
			fmt.Printf("🔴 Expired: %d\n", results.ExpiredCount)
		}
		if results.CriticalCount > 0 {
			fmt.Printf("🟠 Critical (<7 days): %d\n", results.CriticalCount)
		}
		if results.ExpiringCount > 0 {
			fmt.Printf("🟡 Expiring Soon (<30 days): %d\n", results.ExpiringCount)
		}
	}

	// Send Slack alert if configured and certificates are expiring
	if k8sSlackWebhook != "" && len(results.Certificates) > 0 {
		fmt.Println("\n📢 Sending Slack alert...")

		notifier := notify.NewSlackNotifier(k8sSlackWebhook)

		// Build alert message
		message := fmt.Sprintf("Found %d TLS certificate(s) expiring within %d days",
			len(results.Certificates), expiryDays)

		// Create a pseudo-AWS AuditResults for Slack formatting
		// We'll format it as a custom message instead
		err := sendCertSlackAlert(notifier, message, results)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to send Slack alert: %v\n", err)
		} else {
			fmt.Println("✅ Slack alert sent successfully!")
		}
	} else if k8sSlackWebhook != "" {
		fmt.Printf("\nℹ️  Slack webhook configured but no certificates expiring within %d days - no alert sent\n", expiryDays)
	}

	return nil
}

// sendCertSlackAlert sends a certificate expiry alert to Slack
func sendCertSlackAlert(notifier *notify.SlackNotifier, message string, results *k8s.CertificateResults) error {
	// For now, we'll use a simple text message
	// TODO: Implement proper Slack message formatting for certificates
	slackMsg := notify.SlackMessage{
		Text: fmt.Sprintf(":lock: *Kubernetes TLS Certificate Expiry Alert*\n%s", message),
		Attachments: []notify.Attachment{
			{
				Color: determineCertColor(results),
				Text:  formatCertFindings(results),
				Fields: []notify.Field{
					{
						Title: ":calendar: Certificates Found",
						Value: fmt.Sprintf("%d", len(results.Certificates)),
						Short: true,
					},
					{
						Title: ":warning: Critical (<7 days)",
						Value: fmt.Sprintf("%d", results.CriticalCount),
						Short: true,
					},
					{
						Title: ":hourglass: Expiring Soon (<30 days)",
						Value: fmt.Sprintf("%d", results.ExpiringCount),
						Short: true,
					},
					{
						Title: ":x: Expired",
						Value: fmt.Sprintf("%d", results.ExpiredCount),
						Short: true,
					},
				},
			},
		},
	}

	// Send using the notifier's internal HTTP client
	return notifier.SendSlackMessage(slackMsg)
}

func determineCertColor(results *k8s.CertificateResults) string {
	if results.ExpiredCount > 0 || results.CriticalCount > 0 {
		return "danger" // Red
	} else if results.ExpiringCount > 0 {
		return "warning" // Yellow
	}
	return "good" // Green
}

func formatCertFindings(results *k8s.CertificateResults) string {
	var text string

	for _, cert := range results.Certificates {
		status := ""
		switch cert.Status {
		case "expired":
			status = "🔴 EXPIRED"
		case "critical":
			status = "🟠 CRITICAL"
		case "expiring-soon":
			status = "🟡 EXPIRING SOON"
		default:
			status = "🟢 VALID"
		}

		text += fmt.Sprintf("%s *%s/%s* - %d days remaining (%s)\n",
			status,
			cert.Namespace,
			cert.SecretName,
			cert.DaysRemaining,
			cert.FormatDNSNames())
	}

	if text == "" {
		text = "✅ All certificates are valid"
	}

	return text
}

func runK8sPDB(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	fmt.Println("🛡️  Checking PodDisruptionBudget status...\n")

	checker, err := k8s.NewHealthChecker()
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Determine namespace
	ns := namespace
	if ns == "" {
		fmt.Println("Scanning all namespaces for PodDisruptionBudgets...\n")
	} else {
		fmt.Printf("Scanning namespace '%s' for PodDisruptionBudgets...\n\n", ns)
	}

	// Check PDB status
	results, err := checker.CheckPDBStatus(ctx, ns)
	if err != nil {
		return fmt.Errorf("failed to check PDBs: %w", err)
	}

	// Display results
	if len(results.PDBs) == 0 {
		fmt.Printf("No PodDisruptionBudgets found (scanned %d namespaces)\n", results.TotalScanned)
	} else {
		fmt.Printf("🛡️  PodDisruptionBudget Status\n")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("%-20s %-25s %-15s %-10s %-10s %s\n",
			"NAMESPACE", "NAME", "MIN AVAIL", "CURRENT", "ALLOWED", "STATUS")
		fmt.Println("────────────────────┼─────────────────────────┼───────────────┼──────────┼──────────┼────────────────────────────────────")

		// Print each PDB with color coding
		for _, pdb := range results.PDBs {
			color := pdb.GetColorCode()
			reset := k8s.ResetColor()

			// Truncate names if too long
			ns := pdb.Namespace
			if len(ns) > 18 {
				ns = ns[:15] + "..."
			}

			name := pdb.Name
			if len(name) > 23 {
				name = name[:20] + "..."
			}

			minAvail := pdb.FormatMinAvailable()
			if len(minAvail) > 13 {
				minAvail = minAvail[:10] + "..."
			}

			fmt.Printf("%s%-20s %-25s %-15s %-10d %-10d %s%s\n",
				color,
				ns,
				name,
				minAvail,
				pdb.CurrentHealthy,
				pdb.DisruptionsAllowed,
				pdb.GetStatusDisplay(),
				reset)
		}

		// Print summary
		fmt.Println("\nSummary:")
		if results.HealthyCount > 0 {
			fmt.Printf("✅ Healthy: %d\n", results.HealthyCount)
		}
		if results.AtRiskCount > 0 {
			fmt.Printf("⚠️  At-Risk (0 disruptions allowed): %d\n", results.AtRiskCount)
		}
		if results.CriticalCount > 0 {
			fmt.Printf("🔴 Critical (0 disruptions + unhealthy): %d\n", results.CriticalCount)
		}
		if results.NoPodsCount > 0 {
			fmt.Printf("❌ No Matching Pods: %d\n", results.NoPodsCount)
		}
	}

	// Send Slack alert if configured and issues found
	if k8sSlackWebhook != "" && (results.AtRiskCount > 0 || results.CriticalCount > 0 || results.NoPodsCount > 0) {
		fmt.Println("\n📢 Sending Slack alert...")

		notifier := notify.NewSlackNotifier(k8sSlackWebhook)

		// Build alert message
		message := fmt.Sprintf("Found %d PodDisruptionBudget issue(s)",
			results.AtRiskCount+results.CriticalCount+results.NoPodsCount)

		err := sendPDBSlackAlert(notifier, message, results)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to send Slack alert: %v\n", err)
		} else {
			fmt.Println("✅ Slack alert sent successfully!")
		}
	} else if k8sSlackWebhook != "" {
		fmt.Println("\nℹ️  Slack webhook configured but all PDBs are healthy - no alert sent")
	}

	return nil
}

// sendPDBSlackAlert sends a PDB status alert to Slack
func sendPDBSlackAlert(notifier *notify.SlackNotifier, message string, results *k8s.PDBResults) error {
	slackMsg := notify.SlackMessage{
		Text: fmt.Sprintf(":shield: *Kubernetes PodDisruptionBudget Alert*\n%s", message),
		Attachments: []notify.Attachment{
			{
				Color: determinePDBColor(results),
				Text:  formatPDBFindings(results),
				Fields: []notify.Field{
					{
						Title: ":clipboard: Total PDBs",
						Value: fmt.Sprintf("%d", results.TotalScanned),
						Short: true,
					},
					{
						Title: ":warning: At-Risk",
						Value: fmt.Sprintf("%d", results.AtRiskCount),
						Short: true,
					},
					{
						Title: ":red_circle: Critical",
						Value: fmt.Sprintf("%d", results.CriticalCount),
						Short: true,
					},
					{
						Title: ":x: No Matching Pods",
						Value: fmt.Sprintf("%d", results.NoPodsCount),
						Short: true,
					},
				},
			},
		},
	}

	return notifier.SendSlackMessage(slackMsg)
}

func determinePDBColor(results *k8s.PDBResults) string {
	if results.CriticalCount > 0 {
		return "danger" // Red
	} else if results.AtRiskCount > 0 || results.NoPodsCount > 0 {
		return "warning" // Yellow
	}
	return "good" // Green
}

func formatPDBFindings(results *k8s.PDBResults) string {
	var text string

	for _, pdb := range results.PDBs {
		// Only include non-healthy PDBs in alert
		if pdb.Status == "healthy" {
			continue
		}

		status := ""
		switch pdb.Status {
		case "critical":
			status = "🔴 CRITICAL"
		case "at-risk":
			status = "🟡 AT-RISK"
		case "no-pods":
			status = "⚪ NO-PODS"
		}

		text += fmt.Sprintf("%s *%s/%s* - %s\n",
			status,
			pdb.Namespace,
			pdb.Name,
			pdb.StatusMessage)
	}

	if text == "" {
		text = "✅ All PDBs are healthy"
	}

	return text
}

