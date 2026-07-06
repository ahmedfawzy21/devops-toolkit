package eks

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NamespaceCostAuditor allocates cluster node spend across namespaces by their
// reserved-capacity share. It reads reserved-capacity metrics from CloudWatch
// Container Insights and node inventory from the Kubernetes API.
type NamespaceCostAuditor struct {
	clientset        *kubernetes.Clientset
	cloudwatchClient *cloudwatch.Client
	region           string
}

// NamespaceCost is the cost attributed to a single namespace.
type NamespaceCost struct {
	Namespace             string
	CPUReservedPercent    float64
	MemoryReservedPercent float64
	MonthlyCost           float64
	PercentOfClusterCost  float64
}

// namespaceReservation is the intermediate reserved-capacity reading for a
// namespace, used as input to the (pure) allocation step.
type namespaceReservation struct {
	Namespace             string
	CPUReservedPercent    float64
	MemoryReservedPercent float64
}

// NewNamespaceCostAuditor builds a NamespaceCostAuditor from the local
// kubeconfig and the default AWS SDK config for the given region.
func NewNamespaceCostAuditor(ctx context.Context, region string) (*NamespaceCostAuditor, error) {
	clientset, err := newKubernetesClientset()
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &NamespaceCostAuditor{
		clientset:        clientset,
		cloudwatchClient: cloudwatch.NewFromConfig(cfg),
		region:           region,
	}, nil
}

// GetNamespaceCostBreakdown attributes the cluster's total node cost across
// namespaces proportionally to their reserved CPU+memory capacity share, as
// reported by Container Insights. Results are sorted by cost descending.
//
// Requires Container Insights to be enabled; the discovery step returns a
// clear error otherwise.
func (a *NamespaceCostAuditor) GetNamespaceCostBreakdown(ctx context.Context) ([]NamespaceCost, error) {
	clusterName, err := discoverClusterName(ctx, a.cloudwatchClient, a.region)
	if err != nil {
		return nil, err
	}

	totalClusterCost, err := a.totalClusterNodeCost(ctx)
	if err != nil {
		return nil, err
	}

	namespaces, err := discoverNamespaces(ctx, a.cloudwatchClient, clusterName)
	if err != nil {
		return nil, err
	}

	reservations := make([]namespaceReservation, 0, len(namespaces))
	for _, ns := range namespaces {
		dims := namespaceDimensions(clusterName, ns)

		cpu, _, err := metricAverageForDimensions(ctx, a.cloudwatchClient, "pod_cpu_reserved_capacity", dims)
		if err != nil {
			return nil, err
		}

		mem, _, err := metricAverageForDimensions(ctx, a.cloudwatchClient, "pod_memory_reserved_capacity", dims)
		if err != nil {
			return nil, err
		}

		reservations = append(reservations, namespaceReservation{
			Namespace:             ns,
			CPUReservedPercent:    cpu,
			MemoryReservedPercent: mem,
		})
	}

	return allocateNamespaceCosts(reservations, totalClusterCost), nil
}

// totalClusterNodeCost sums the estimated monthly On-Demand cost of every node
// in the cluster, using the same instance-type lookup as the node auditor.
func (a *NamespaceCostAuditor) totalClusterNodeCost(ctx context.Context) (float64, error) {
	nodes, err := a.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to list nodes: %w", err)
	}

	total := 0.0
	for _, node := range nodes.Items {
		total += nodeMonthlyCost(nodeInstanceType(node.Labels))
	}
	return total, nil
}

// discoverNamespaces returns the distinct namespaces that have reserved-capacity
// metrics published under the given cluster in Container Insights.
func discoverNamespaces(ctx context.Context, cw *cloudwatch.Client, clusterName string) ([]string, error) {
	out, err := cw.ListMetrics(ctx, &cloudwatch.ListMetricsInput{
		Namespace:  aws.String(containerInsightsNamespace),
		MetricName: aws.String("pod_cpu_reserved_capacity"),
		Dimensions: []cloudwatchtypes.DimensionFilter{
			{Name: aws.String("ClusterName"), Value: aws.String(clusterName)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespace metrics: %w", err)
	}

	seen := make(map[string]bool)
	namespaces := make([]string, 0)
	for _, m := range out.Metrics {
		for _, d := range m.Dimensions {
			if aws.ToString(d.Name) != "Namespace" {
				continue
			}
			ns := aws.ToString(d.Value)
			if ns != "" && !seen[ns] {
				seen[ns] = true
				namespaces = append(namespaces, ns)
			}
		}
	}

	return namespaces, nil
}

// namespaceDimensions builds the CloudWatch dimension set for per-namespace
// reserved-capacity metrics.
func namespaceDimensions(clusterName, namespace string) []cloudwatchtypes.Dimension {
	return []cloudwatchtypes.Dimension{
		{Name: aws.String("ClusterName"), Value: aws.String(clusterName)},
		{Name: aws.String("Namespace"), Value: aws.String(namespace)},
	}
}

// allocateNamespaceCosts splits totalClusterCost across namespaces in
// proportion to each namespace's combined CPU+memory reserved-capacity weight.
// It is pure and defensive about a zero total weight (every namespace then gets
// a zero cost rather than producing NaN).
func allocateNamespaceCosts(reservations []namespaceReservation, totalClusterCost float64) []NamespaceCost {
	totalWeight := 0.0
	for _, r := range reservations {
		totalWeight += r.CPUReservedPercent + r.MemoryReservedPercent
	}

	costs := make([]NamespaceCost, 0, len(reservations))
	for _, r := range reservations {
		weight := r.CPUReservedPercent + r.MemoryReservedPercent

		share := 0.0
		cost := 0.0
		if totalWeight > 0 {
			share = weight / totalWeight
			cost = totalClusterCost * share
		}

		costs = append(costs, NamespaceCost{
			Namespace:             r.Namespace,
			CPUReservedPercent:    r.CPUReservedPercent,
			MemoryReservedPercent: r.MemoryReservedPercent,
			MonthlyCost:           cost,
			PercentOfClusterCost:  share * 100,
		})
	}

	sort.Slice(costs, func(i, j int) bool {
		return costs[i].MonthlyCost > costs[j].MonthlyCost
	})

	return costs
}
