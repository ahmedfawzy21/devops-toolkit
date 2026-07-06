package eks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// minSupportedEKSVersion is the oldest Kubernetes minor version treated as
	// supported. Clusters below this are flagged as EOL or approaching EOL. AWS
	// drops support on a rolling basis; 1.28 is used as the mid-2026 floor.
	minSupportedEKSVersion = "1.28"

	// severityCritical / severityWarning label the seriousness of a finding.
	severityCritical = "critical"
	severityWarning  = "warning"

	// openCIDR is the "anywhere" IPv4 CIDR that makes a public endpoint fully
	// exposed.
	openCIDR = "0.0.0.0/0"
)

// EKSSecurityAuditor inspects EKS clusters (control-plane exposure, version) and
// their workloads (containers running as root).
type EKSSecurityAuditor struct {
	eksClient *eks.Client
	clientset *kubernetes.Clientset
	region    string
}

// EKSSecurityFinding describes a single EKS security issue. Cluster-level
// findings leave Namespace/PodName empty; pod-level findings leave the
// version/severity-version fields empty.
type EKSSecurityFinding struct {
	ClusterName    string
	Namespace      string
	PodName        string
	Issue          string // "public_endpoint", "root_container", "outdated_version"
	CurrentVersion string
	MinimumVersion string
	Severity       string // "critical" or "warning"
	RiskNote       string
}

// NewEKSSecurityAuditor builds an EKSSecurityAuditor, pairing an EKS client
// (control-plane checks) with a Kubernetes clientset from the local kubeconfig
// (workload checks).
func NewEKSSecurityAuditor(ctx context.Context, region string) (*EKSSecurityAuditor, error) {
	clientset, err := newKubernetesClientset()
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &EKSSecurityAuditor{
		eksClient: eks.NewFromConfig(cfg),
		clientset: clientset,
		region:    region,
	}, nil
}

// FindPublicEndpointClusters flags clusters whose API server endpoint is
// publicly accessible from anywhere (0.0.0.0/0), rather than restricted to
// specific CIDRs.
func (a *EKSSecurityAuditor) FindPublicEndpointClusters(ctx context.Context) ([]EKSSecurityFinding, error) {
	names, err := a.listClusters(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]EKSSecurityFinding, 0)
	for _, name := range names {
		out, err := a.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
		if err != nil {
			return nil, fmt.Errorf("failed to describe cluster %s: %w", name, err)
		}

		cluster := out.Cluster
		if cluster == nil || cluster.ResourcesVpcConfig == nil {
			continue
		}

		vpc := cluster.ResourcesVpcConfig
		if !vpc.EndpointPublicAccess || !containsOpenCIDR(vpc.PublicAccessCidrs) {
			continue
		}

		findings = append(findings, EKSSecurityFinding{
			ClusterName: name,
			Issue:       "public_endpoint",
			Severity:    severityCritical,
			RiskNote:    "API server endpoint is publicly accessible from 0.0.0.0/0; restrict PublicAccessCidrs or disable public access",
		})
	}

	return findings, nil
}

// FindPodsRunningAsRoot lists pods (all namespaces when namespace is empty) and
// flags those with at least one container that runs, or may run, as root. It
// evaluates both pod-level and container-level security contexts.
func (a *EKSSecurityAuditor) FindPodsRunningAsRoot(ctx context.Context, namespace string) ([]EKSSecurityFinding, error) {
	pods, err := a.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	findings := make([]EKSSecurityFinding, 0)
	for _, pod := range pods.Items {
		if finding, ok := analyzePodRootRisk(pod); ok {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// FindOutdatedClusterVersions flags clusters whose Kubernetes version is below
// the minimum supported version.
func (a *EKSSecurityAuditor) FindOutdatedClusterVersions(ctx context.Context) ([]EKSSecurityFinding, error) {
	names, err := a.listClusters(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]EKSSecurityFinding, 0)
	for _, name := range names {
		out, err := a.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
		if err != nil {
			return nil, fmt.Errorf("failed to describe cluster %s: %w", name, err)
		}

		cluster := out.Cluster
		if cluster == nil {
			continue
		}

		version := aws.ToString(cluster.Version)
		if !versionBelowMinimum(version, minSupportedEKSVersion) {
			continue
		}

		findings = append(findings, EKSSecurityFinding{
			ClusterName:    name,
			Issue:          "outdated_version",
			CurrentVersion: version,
			MinimumVersion: minSupportedEKSVersion,
			Severity:       severityCritical,
			RiskNote:       fmt.Sprintf("cluster version %s is below the minimum supported %s (EOL or approaching EOL; no security patches)", version, minSupportedEKSVersion),
		})
	}

	return findings, nil
}

// listClusters returns every EKS cluster name in the region, following
// pagination.
func (a *EKSSecurityAuditor) listClusters(ctx context.Context) ([]string, error) {
	names := make([]string, 0)
	var nextToken *string

	for {
		out, err := a.eksClient.ListClusters(ctx, &eks.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("failed to list clusters: %w", err)
		}

		names = append(names, out.Clusters...)

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return names, nil
}

// analyzePodRootRisk evaluates a pod's containers and returns a single finding
// for the most severe root-related issue, if any. It is pure so the logic is
// testable without a live cluster.
func analyzePodRootRisk(pod corev1.Pod) (EKSSecurityFinding, bool) {
	var worst EKSSecurityFinding
	flagged := false

	for _, container := range pod.Spec.Containers {
		uid := effectiveRunAsUser(pod.Spec.SecurityContext, container.SecurityContext)
		nonRoot := effectiveRunAsNonRoot(pod.Spec.SecurityContext, container.SecurityContext)

		isRoot, severity, note := evaluateRootRisk(uid, nonRoot)
		if !isRoot {
			continue
		}

		// Prefer a critical finding over a warning when both appear in a pod.
		if !flagged || (severity == severityCritical && worst.Severity == severityWarning) {
			worst = EKSSecurityFinding{
				Namespace: pod.Namespace,
				PodName:   pod.Name,
				Issue:     "root_container",
				Severity:  severity,
				RiskNote:  fmt.Sprintf("container %q: %s", container.Name, note),
			}
			flagged = true
		}
	}

	return worst, flagged
}

// effectiveRunAsUser resolves the RunAsUser that applies to a container,
// preferring the container-level setting over the pod-level one.
func effectiveRunAsUser(podSC *corev1.PodSecurityContext, cSC *corev1.SecurityContext) *int64 {
	if cSC != nil && cSC.RunAsUser != nil {
		return cSC.RunAsUser
	}
	if podSC != nil && podSC.RunAsUser != nil {
		return podSC.RunAsUser
	}
	return nil
}

// effectiveRunAsNonRoot resolves the RunAsNonRoot that applies to a container,
// preferring the container-level setting over the pod-level one.
func effectiveRunAsNonRoot(podSC *corev1.PodSecurityContext, cSC *corev1.SecurityContext) *bool {
	if cSC != nil && cSC.RunAsNonRoot != nil {
		return cSC.RunAsNonRoot
	}
	if podSC != nil && podSC.RunAsNonRoot != nil {
		return podSC.RunAsNonRoot
	}
	return nil
}

// evaluateRootRisk classifies a container's effective UID / RunAsNonRoot into a
// root-risk verdict. An explicit non-zero UID or RunAsNonRoot=true is safe; UID
// 0 or RunAsNonRoot=false is critical; an entirely unset context is a warning
// (the image decides, which may be root).
func evaluateRootRisk(uid *int64, nonRoot *bool) (bool, string, string) {
	if uid != nil {
		if *uid == 0 {
			return true, severityCritical, "runs as root (RunAsUser is 0)"
		}
		return false, "", ""
	}

	if nonRoot != nil {
		if !*nonRoot {
			return true, severityCritical, "RunAsNonRoot is false; permitted to run as root"
		}
		return false, "", ""
	}

	return true, severityWarning, "no RunAsNonRoot or RunAsUser set; runs as whatever UID the image specifies (possibly root)"
}

// containsOpenCIDR reports whether the CIDR list contains the fully-open
// 0.0.0.0/0 block.
func containsOpenCIDR(cidrs []string) bool {
	for _, cidr := range cidrs {
		if cidr == openCIDR {
			return true
		}
	}
	return false
}

// versionBelowMinimum reports whether a Kubernetes "major.minor" version string
// is strictly below the given minimum. Unparseable versions return false (they
// are not flagged rather than falsely reported).
func versionBelowMinimum(current, minimum string) bool {
	curMajor, curMinor, ok := parseK8sVersion(current)
	if !ok {
		return false
	}
	minMajor, minMinor, ok := parseK8sVersion(minimum)
	if !ok {
		return false
	}

	if curMajor != minMajor {
		return curMajor < minMajor
	}
	return curMinor < minMinor
}

// parseK8sVersion parses a "major.minor" version (tolerating a leading "v" and a
// trailing ".patch" or "+build" suffix) into its integer components.
func parseK8sVersion(v string) (int, int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return 0, 0, false
	}

	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}

	// Trim any "+build" or "-eks" suffix from the minor component.
	minorStr := parts[1]
	for i, r := range minorStr {
		if r < '0' || r > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, false
	}

	return major, minor, true
}
