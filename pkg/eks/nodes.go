package eks

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	awspkg "github.com/ahmedfawzy/devops-toolkit/pkg/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	// containerInsightsNamespace is the CloudWatch namespace where the EKS
	// CloudWatch agent / amazon-cloudwatch-observability addon publishes
	// Container Insights metrics.
	containerInsightsNamespace = "ContainerInsights"

	// underutilizedThreshold flags a node only when BOTH average CPU and
	// memory utilization fall below this percentage.
	underutilizedThreshold = 30.0

	// metricLookbackDays is the trailing window used when averaging
	// Container Insights metrics.
	metricLookbackDays = 7
)

// NodeAuditor inspects EKS worker nodes for underutilization. It pairs a
// Kubernetes clientset (to enumerate nodes and read their labels) with a
// CloudWatch client (to read Container Insights utilization metrics).
type NodeAuditor struct {
	clientset        *kubernetes.Clientset
	cloudwatchClient *cloudwatch.Client
	region           string
}

// NodeFinding describes a single underutilized node and a rightsizing
// suggestion.
type NodeFinding struct {
	NodeName         string
	InstanceType     string
	AvgCPUPercent    float64
	AvgMemoryPercent float64
	MonthlyCost      float64
	Recommendation   string
}

// NewNodeAuditor builds a NodeAuditor. The Kubernetes client is constructed
// from the local kubeconfig (matching pkg/k8s), and the CloudWatch client from
// the default AWS SDK config for the given region.
func NewNodeAuditor(ctx context.Context, region string) (*NodeAuditor, error) {
	clientset, err := newKubernetesClientset()
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &NodeAuditor{
		clientset:        clientset,
		cloudwatchClient: cloudwatch.NewFromConfig(cfg),
		region:           region,
	}, nil
}

// FindUnderutilizedNodes lists cluster nodes and flags those whose 7-day
// average CPU and memory utilization are both below underutilizedThreshold,
// estimating monthly cost from the node's instance type and suggesting one
// size class down.
//
// Both node_cpu_utilization and node_memory_utilization come from CloudWatch
// Container Insights. If Container Insights is not enabled on the cluster the
// discovery step returns a clear, actionable error rather than silently
// reporting zero findings.
func (a *NodeAuditor) FindUnderutilizedNodes(ctx context.Context) ([]NodeFinding, error) {
	clusterName, err := discoverClusterName(ctx, a.cloudwatchClient, a.region)
	if err != nil {
		return nil, err
	}

	nodes, err := a.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	findings := make([]NodeFinding, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		cpuAvg, cpuOK, err := metricAverageForDimensions(ctx, a.cloudwatchClient, "node_cpu_utilization", nodeDimensions(clusterName, node.Name))
		if err != nil {
			return nil, fmt.Errorf("failed to get CPU metrics for node %s: %w", node.Name, err)
		}

		memAvg, memOK, err := metricAverageForDimensions(ctx, a.cloudwatchClient, "node_memory_utilization", nodeDimensions(clusterName, node.Name))
		if err != nil {
			return nil, fmt.Errorf("failed to get memory metrics for node %s: %w", node.Name, err)
		}

		// A node with no datapoints (e.g. just joined) can't be judged; skip
		// rather than flag it as 0% utilized.
		if !cpuOK || !memOK {
			continue
		}

		// Flag only when BOTH dimensions are underutilized.
		if cpuAvg >= underutilizedThreshold || memAvg >= underutilizedThreshold {
			continue
		}

		instanceType := nodeInstanceType(node.Labels)
		findings = append(findings, NodeFinding{
			NodeName:         node.Name,
			InstanceType:     instanceType,
			AvgCPUPercent:    cpuAvg,
			AvgMemoryPercent: memAvg,
			MonthlyCost:      nodeMonthlyCost(instanceType),
			Recommendation:   recommendSmallerInstance(instanceType),
		})
	}

	return findings, nil
}

// newKubernetesClientset loads the local kubeconfig and builds a clientset,
// matching the construction in pkg/k8s/health.go. Shared by every K8s-backed
// auditor in this package.
func newKubernetesClientset() (*kubernetes.Clientset, error) {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return clientset, nil
}

// discoverClusterName finds the EKS cluster name by inspecting the dimensions
// of Container Insights metrics. This doubles as the "is Container Insights
// enabled?" probe: if no such metrics exist, it returns an actionable error.
func discoverClusterName(ctx context.Context, cw *cloudwatch.Client, region string) (string, error) {
	out, err := cw.ListMetrics(ctx, &cloudwatch.ListMetricsInput{
		Namespace:  aws.String(containerInsightsNamespace),
		MetricName: aws.String("node_cpu_utilization"),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list Container Insights metrics: %w", err)
	}

	for _, m := range out.Metrics {
		for _, d := range m.Dimensions {
			if aws.ToString(d.Name) == "ClusterName" {
				return aws.ToString(d.Value), nil
			}
		}
	}

	return "", fmt.Errorf("Container Insights does not appear to be enabled in region %s "+
		"(no %q metrics found). Enable it by installing the amazon-cloudwatch-observability "+
		"EKS addon (or deploying the CloudWatch agent), then retry once metrics have populated",
		region, containerInsightsNamespace)
}

// nodeDimensions builds the CloudWatch dimension set for per-node Container
// Insights metrics.
func nodeDimensions(clusterName, nodeName string) []cloudwatchtypes.Dimension {
	return []cloudwatchtypes.Dimension{
		{Name: aws.String("ClusterName"), Value: aws.String(clusterName)},
		{Name: aws.String("NodeName"), Value: aws.String(nodeName)},
	}
}

// metricAverageForDimensions returns the 7-day average of a Container Insights
// metric for the given dimension set. The bool reports whether any datapoints
// were returned (false means "no data", distinct from a genuine 0% average).
func metricAverageForDimensions(ctx context.Context, cw *cloudwatch.Client, metricName string, dims []cloudwatchtypes.Dimension) (float64, bool, error) {
	endTime := time.Now()
	startTime := endTime.Add(-metricLookbackDays * 24 * time.Hour)

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(containerInsightsNamespace),
		MetricName: aws.String(metricName),
		Dimensions: dims,
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(3600), // 1 hour periods
		Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticAverage},
	}

	result, err := cw.GetMetricStatistics(ctx, input)
	if err != nil {
		return 0, false, fmt.Errorf("failed to get metric statistics for %s: %w", metricName, err)
	}

	if len(result.Datapoints) == 0 {
		return 0, false, nil
	}

	var sum float64
	for _, dp := range result.Datapoints {
		sum += aws.ToFloat64(dp.Average)
	}

	return sum / float64(len(result.Datapoints)), true, nil
}

// nodeInstanceType reads the node's instance type from its labels, preferring
// the stable label and falling back to the deprecated beta label.
func nodeInstanceType(labels map[string]string) string {
	if v, ok := labels["node.kubernetes.io/instance-type"]; ok {
		return v
	}
	if v, ok := labels["beta.kubernetes.io/instance-type"]; ok {
		return v
	}
	return ""
}

// nodeMonthlyCost estimates a node's On-Demand monthly cost, reusing the
// shared pricing tables from pkg/aws. Unknown instance types return 0.
func nodeMonthlyCost(instanceType string) float64 {
	hourly, ok := awspkg.EC2OnDemandHourly[instanceType]
	if !ok {
		return 0
	}
	return awspkg.MonthlyFromHourly(hourly)
}

// instanceSizeDown maps an instance type to one size class smaller within the
// same family. Coverage mirrors the families in awspkg.EC2OnDemandHourly.
var instanceSizeDown = map[string]string{
	"t3.large":   "t3.medium",
	"t3.medium":  "t3.small",
	"t3.small":   "t3.micro",
	"m5.2xlarge": "m5.xlarge",
	"m5.xlarge":  "m5.large",
	"c5.xlarge":  "c5.large",
	"r5.xlarge":  "r5.large",
}

// nextSmallerInstance returns the next size class down, if one is known.
func nextSmallerInstance(instanceType string) (string, bool) {
	smaller, ok := instanceSizeDown[instanceType]
	return smaller, ok
}

// recommendSmallerInstance produces a human-readable rightsizing suggestion.
func recommendSmallerInstance(instanceType string) string {
	if instanceType == "" {
		return "instance type unknown; review utilization manually"
	}

	smaller, ok := nextSmallerInstance(instanceType)
	if !ok {
		return fmt.Sprintf("%s is already the smallest known size in its family; consider consolidating workloads", instanceType)
	}

	return fmt.Sprintf("downsize %s -> %s (~$%.2f/mo saved)", instanceType, smaller, instanceRightsizeSavings(instanceType))
}

// instanceRightsizeSavings estimates the monthly saving from moving one size
// class down. Returns 0 when there is no smaller size or pricing is unknown.
func instanceRightsizeSavings(instanceType string) float64 {
	smaller, ok := nextSmallerInstance(instanceType)
	if !ok {
		return 0
	}

	saving := nodeMonthlyCost(instanceType) - nodeMonthlyCost(smaller)
	if saving < 0 {
		return 0
	}
	return saving
}
