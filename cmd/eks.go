package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ahmedfawzy/devops-toolkit/pkg/eks"
	"github.com/ahmedfawzy/devops-toolkit/pkg/reporter"
	"github.com/spf13/cobra"
)

var (
	eksRegion          string
	eksCluster         string
	eksNamespace       string
	eksAuditNodes      bool
	eksAuditNamespaces bool
)

var eksCmd = &cobra.Command{
	Use:   "eks",
	Short: "EKS cost intelligence and rightsizing",
	Long:  "Audit EKS clusters for underutilized nodes, missing pod resource limits, namespace cost allocation, and Spot/On-Demand balance",
	// Findings are produced by live AWS/Kubernetes calls; on a runtime failure
	// the actionable guidance is more useful than a cobra usage dump.
	SilenceUsage: true,
}

var eksNodesCmd = &cobra.Command{
	Use:   "nodes",
	Short: "Find underutilized EKS nodes",
	Long: `Scan EKS worker nodes for rightsizing opportunities:

- Reads 7-day average CPU and memory utilization from CloudWatch Container Insights
- Flags nodes where BOTH CPU and memory average below 30%
- Estimates monthly cost from the node's instance type
- Recommends one instance size class down

Requires CloudWatch Container Insights to be enabled on the cluster.

Example:
  dtk eks nodes --cluster my-cluster --region us-east-1
  dtk eks nodes --cluster my-cluster --region eu-west-1 --format json`,
	RunE: runEKSNodes,
}

var eksPodsCmd = &cobra.Command{
	Use:   "pods",
	Short: "Find pods without resource requests/limits",
	Long: `Scan pods for missing CPU/memory requests and limits:

- Inspects every container's resource requests and limits
- Flags any missing setting (a pod can be partially specified)
- Explains the practical risk (OOMKill, noisy-neighbor CPU starvation, overcommit)

Pure Kubernetes API via your local kubeconfig; no AWS access or Container Insights needed.

Example:
  dtk eks pods
  dtk eks pods --namespace production
  dtk eks pods --format json`,
	RunE: runEKSPods,
}

var eksNamespacesCmd = &cobra.Command{
	Use:   "namespaces",
	Short: "Break down cluster cost by namespace",
	Long: `Allocate cluster node cost across namespaces by reserved-capacity share:

- Reads pod_cpu_reserved_capacity and pod_memory_reserved_capacity from Container Insights
- Sums node cost across the cluster and allocates it proportionally per namespace
- Sorts namespaces by attributed monthly cost (descending)

Requires CloudWatch Container Insights to be enabled on the cluster.

Example:
  dtk eks namespaces --cluster my-cluster --region us-east-1
  dtk eks namespaces --cluster my-cluster --region eu-west-1 --format json`,
	RunE: runEKSNamespaces,
}

var eksNodeGroupsCmd = &cobra.Command{
	Use:   "nodegroups",
	Short: "Show Spot/On-Demand ratio per node group",
	Long: `Report the Spot vs On-Demand capacity mix of each node group:

- Uses the managed node group CapacityType where available
- Falls back to per-instance EC2 lifecycle inspection for self-managed/Karpenter groups
- Roughly estimates savings from shifting some On-Demand capacity to Spot when
  a group is more than 70% On-Demand

Example:
  dtk eks nodegroups --cluster my-cluster --region us-east-1
  dtk eks nodegroups --cluster my-cluster --region eu-west-1 --format json`,
	RunE: runEKSNodeGroups,
}

var eksAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run the combined EKS audit",
	Long: `Run all EKS-layer checks and print a combined savings summary:

Always-on checks (no Container Insights dependency):
- Pods missing resource requests/limits
- Node group Spot/On-Demand ratio

Opt-in checks (disabled by default; require Container Insights):
- Underutilized nodes via --nodes
- Namespace cost breakdown via --namespaces

When an opt-in check is enabled but Container Insights is not available, the
audit prints enablement guidance and continues with the remaining checks.

Example:
  dtk eks audit --cluster my-cluster --region us-east-1
  dtk eks audit --cluster my-cluster --region us-east-1 --nodes --namespaces
  dtk eks audit --cluster my-cluster --region us-east-1 --format json`,
	RunE: runEKSAudit,
}

func init() {
	rootCmd.AddCommand(eksCmd)
	eksCmd.AddCommand(eksNodesCmd)
	eksCmd.AddCommand(eksPodsCmd)
	eksCmd.AddCommand(eksNamespacesCmd)
	eksCmd.AddCommand(eksNodeGroupsCmd)
	eksCmd.AddCommand(eksAuditCmd)

	// nodes: needs region + cluster (Container Insights is scoped per-cluster).
	eksNodesCmd.Flags().StringVarP(&eksRegion, "region", "r", "", "AWS region")
	eksNodesCmd.Flags().StringVarP(&eksCluster, "cluster", "c", "", "EKS cluster name (required)")
	eksNodesCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
	_ = eksNodesCmd.MarkFlagRequired("cluster")

	// pods: pure K8s API, optional namespace (empty = all namespaces).
	eksPodsCmd.Flags().StringVarP(&eksNamespace, "namespace", "n", "", "Kubernetes namespace (default: all namespaces)")
	eksPodsCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	// namespaces: needs region + cluster.
	eksNamespacesCmd.Flags().StringVarP(&eksRegion, "region", "r", "", "AWS region")
	eksNamespacesCmd.Flags().StringVarP(&eksCluster, "cluster", "c", "", "EKS cluster name (required)")
	eksNamespacesCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
	_ = eksNamespacesCmd.MarkFlagRequired("cluster")

	// nodegroups: needs region + cluster.
	eksNodeGroupsCmd.Flags().StringVarP(&eksRegion, "region", "r", "", "AWS region")
	eksNodeGroupsCmd.Flags().StringVarP(&eksCluster, "cluster", "c", "", "EKS cluster name (required)")
	eksNodeGroupsCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
	_ = eksNodeGroupsCmd.MarkFlagRequired("cluster")

	// audit: needs region + cluster (nodegroups runs by default); CI checks opt-in.
	eksAuditCmd.Flags().StringVarP(&eksRegion, "region", "r", "", "AWS region")
	eksAuditCmd.Flags().StringVarP(&eksCluster, "cluster", "c", "", "EKS cluster name (required)")
	eksAuditCmd.Flags().StringVarP(&eksNamespace, "namespace", "n", "", "Kubernetes namespace for the pod check (default: all namespaces)")
	eksAuditCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
	eksAuditCmd.Flags().BoolVar(&eksAuditNodes, "nodes", false, "Include underutilized node analysis (opt-in; requires Container Insights)")
	eksAuditCmd.Flags().BoolVar(&eksAuditNamespaces, "namespaces", false, "Include namespace cost breakdown (opt-in; requires Container Insights)")
	_ = eksAuditCmd.MarkFlagRequired("cluster")
}

func resolveEKSRegion() string {
	if eksRegion != "" {
		return eksRegion
	}
	if region := os.Getenv("AWS_REGION"); region != "" {
		return region
	}
	return "us-east-1"
}

// isContainerInsightsNotEnabled reports whether err is the "Container Insights
// not enabled" condition surfaced by pkg/eks.
func isContainerInsightsNotEnabled(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Container Insights")
}

// printContainerInsightsGuidance prints clear, actionable enablement steps.
func printContainerInsightsGuidance(region string) {
	fmt.Println("⚠️  Container Insights does not appear to be enabled on this cluster.")
	fmt.Println("   Node- and namespace-level metrics are read from CloudWatch Container Insights.")
	fmt.Println("   Enable the managed EKS addon, then retry once metrics have populated (a few minutes):")
	fmt.Printf("     aws eks create-addon --cluster-name %s --addon-name amazon-cloudwatch-observability --region %s\n",
		valueOrPlaceholder(eksCluster, "<cluster>"), region)
	fmt.Println("   (or deploy the CloudWatch agent / amazon-cloudwatch-observability Helm chart)")
}

func valueOrPlaceholder(v, placeholder string) string {
	if v == "" {
		return placeholder
	}
	return v
}

func runEKSNodes(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveEKSRegion()

	fmt.Printf("🔍 Scanning EKS nodes in cluster %q (%s)...\n\n", eksCluster, region)

	auditor, err := eks.NewNodeAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create EKS node auditor: %w", err)
	}

	findings, err := auditor.FindUnderutilizedNodes(ctx)
	if err != nil {
		if isContainerInsightsNotEnabled(err) {
			printContainerInsightsGuidance(region)
			return errors.New("Container Insights not enabled on cluster")
		}
		return fmt.Errorf("failed to find underutilized nodes: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderEKSNodeResults(findings); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runEKSPods(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if eksNamespace == "" {
		fmt.Print("🔍 Scanning all namespaces for pods without resource requests/limits...\n\n")
	} else {
		fmt.Printf("🔍 Scanning namespace %q for pods without resource requests/limits...\n\n", eksNamespace)
	}

	auditor, err := eks.NewPodAuditor(ctx)
	if err != nil {
		return fmt.Errorf("failed to create EKS pod auditor: %w", err)
	}

	findings, err := auditor.FindPodsWithoutResourceLimits(ctx, eksNamespace)
	if err != nil {
		return fmt.Errorf("failed to find pods without resource limits: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderEKSPodResults(findings); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runEKSNamespaces(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveEKSRegion()

	fmt.Printf("🔍 Breaking down cost by namespace for cluster %q (%s)...\n\n", eksCluster, region)

	auditor, err := eks.NewNamespaceCostAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create EKS namespace cost auditor: %w", err)
	}

	costs, err := auditor.GetNamespaceCostBreakdown(ctx)
	if err != nil {
		if isContainerInsightsNotEnabled(err) {
			printContainerInsightsGuidance(region)
			return errors.New("Container Insights not enabled on cluster")
		}
		return fmt.Errorf("failed to get namespace cost breakdown: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderEKSNamespaceResults(costs); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runEKSNodeGroups(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveEKSRegion()

	fmt.Printf("🔍 Inspecting node group capacity mix for cluster %q (%s)...\n\n", eksCluster, region)

	auditor, err := eks.NewNodeGroupAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create EKS node group auditor: %w", err)
	}

	ratios, err := auditor.GetSpotRatioByNodeGroup(ctx, eksCluster)
	if err != nil {
		return fmt.Errorf("failed to get node group Spot ratio: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderEKSNodeGroupResults(ratios); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runEKSAudit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveEKSRegion()

	fmt.Printf("🔍 Auditing EKS cluster %q (%s)...\n\n", eksCluster, region)

	results := &eks.Results{}

	// Always-on: pods missing resource requests/limits (pure K8s API).
	fmt.Println("📦 Checking pods for missing resource requests/limits...")
	podAuditor, err := eks.NewPodAuditor(ctx)
	if err != nil {
		return fmt.Errorf("failed to create EKS pod auditor: %w", err)
	}
	pods, err := podAuditor.FindPodsWithoutResourceLimits(ctx, eksNamespace)
	if err != nil {
		return fmt.Errorf("failed to find pods without resource limits: %w", err)
	}
	results.PodsWithoutLimits = pods

	// Always-on: node group Spot/On-Demand ratio (EKS + EC2 APIs).
	fmt.Println("⚖️  Checking node group Spot/On-Demand ratio...")
	ngAuditor, err := eks.NewNodeGroupAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create EKS node group auditor: %w", err)
	}
	ratios, err := ngAuditor.GetSpotRatioByNodeGroup(ctx, eksCluster)
	if err != nil {
		return fmt.Errorf("failed to get node group Spot ratio: %w", err)
	}
	results.NodeGroupRatios = ratios

	// Opt-in: underutilized nodes (requires Container Insights).
	if eksAuditNodes {
		fmt.Println("🖥️  Checking for underutilized nodes...")
		nodeAuditor, err := eks.NewNodeAuditor(ctx, region)
		if err != nil {
			return fmt.Errorf("failed to create EKS node auditor: %w", err)
		}
		nodes, err := nodeAuditor.FindUnderutilizedNodes(ctx)
		if err != nil {
			if isContainerInsightsNotEnabled(err) {
				// Don't fail the whole audit; warn and skip this opt-in check.
				printContainerInsightsGuidance(region)
				fmt.Println("   Skipping the underutilized-node check.")
			} else {
				return fmt.Errorf("failed to find underutilized nodes: %w", err)
			}
		} else {
			results.UnderutilizedNodes = nodes
		}
	}

	// Opt-in: namespace cost breakdown (requires Container Insights).
	if eksAuditNamespaces {
		fmt.Println("🏷️  Breaking down cost by namespace...")
		nsAuditor, err := eks.NewNamespaceCostAuditor(ctx, region)
		if err != nil {
			return fmt.Errorf("failed to create EKS namespace cost auditor: %w", err)
		}
		costs, err := nsAuditor.GetNamespaceCostBreakdown(ctx)
		if err != nil {
			if isContainerInsightsNotEnabled(err) {
				printContainerInsightsGuidance(region)
				fmt.Println("   Skipping the namespace cost breakdown.")
			} else {
				return fmt.Errorf("failed to get namespace cost breakdown: %w", err)
			}
		} else {
			results.NamespaceCosts = costs
		}
	}

	results.CalculateSavings()

	fmt.Println()

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderEKSResults(results); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}
