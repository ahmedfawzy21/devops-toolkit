package cmd

import (
	"context"
	"fmt"

	"github.com/ahmedfawzy/devops-toolkit/pkg/k8s"
	"github.com/ahmedfawzy/devops-toolkit/pkg/reporter"
	"github.com/spf13/cobra"
)

var (
	namespace    string
	allNamespaces bool
	checkNodes   bool
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

func init() {
	rootCmd.AddCommand(k8sCmd)
	k8sCmd.AddCommand(k8sHealthCmd)

	k8sHealthCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace (default: all namespaces)")
	k8sHealthCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", true, "Check all namespaces")
	k8sHealthCmd.Flags().BoolVar(&checkNodes, "nodes", true, "Include node health check")
	k8sHealthCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
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
