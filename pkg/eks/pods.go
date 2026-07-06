package eks

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PodAuditor inspects pods for missing resource requests/limits. It is a pure
// Kubernetes-API auditor and needs no AWS client.
type PodAuditor struct {
	clientset *kubernetes.Clientset
}

// PodFinding records, per container, which of the four resource settings are
// missing along with a plain-language risk note.
type PodFinding struct {
	Namespace            string
	PodName              string
	ContainerName        string
	MissingCPURequest    bool
	MissingCPULimit      bool
	MissingMemoryRequest bool
	MissingMemoryLimit   bool
	RiskNote             string
}

// NewPodAuditor builds a PodAuditor from the local kubeconfig, matching the
// construction in pkg/k8s/health.go.
func NewPodAuditor(ctx context.Context) (*PodAuditor, error) {
	clientset, err := newKubernetesClientset()
	if err != nil {
		return nil, err
	}

	return &PodAuditor{clientset: clientset}, nil
}

// FindPodsWithoutResourceLimits lists pods (all namespaces when namespace is
// empty) and returns one finding per container that is missing any CPU/memory
// request or limit. A container can be partially specified (e.g. has a CPU
// request but no memory limit); the finding captures exactly which settings
// are absent.
func (a *PodAuditor) FindPodsWithoutResourceLimits(ctx context.Context, namespace string) ([]PodFinding, error) {
	pods, err := a.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	findings := make([]PodFinding, 0)
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			finding := analyzeContainerResources(pod.Namespace, pod.Name, container)
			if finding.hasMissingResource() {
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// analyzeContainerResources determines which resource settings a container is
// missing and attaches a risk note. It takes a plain corev1.Container so the
// logic is testable without a live cluster.
func analyzeContainerResources(namespace, podName string, container corev1.Container) PodFinding {
	requests := container.Resources.Requests
	limits := container.Resources.Limits

	finding := PodFinding{
		Namespace:            namespace,
		PodName:              podName,
		ContainerName:        container.Name,
		MissingCPURequest:    isResourceMissing(requests, corev1.ResourceCPU),
		MissingCPULimit:      isResourceMissing(limits, corev1.ResourceCPU),
		MissingMemoryRequest: isResourceMissing(requests, corev1.ResourceMemory),
		MissingMemoryLimit:   isResourceMissing(limits, corev1.ResourceMemory),
	}
	finding.RiskNote = riskNote(finding)
	return finding
}

// hasMissingResource reports whether any of the four resource settings are
// absent.
func (f PodFinding) hasMissingResource() bool {
	return f.MissingCPURequest || f.MissingCPULimit ||
		f.MissingMemoryRequest || f.MissingMemoryLimit
}

// isResourceMissing reports whether the named resource is absent or set to
// zero within the given resource list.
func isResourceMissing(list corev1.ResourceList, name corev1.ResourceName) bool {
	if list == nil {
		return true
	}
	q, ok := list[name]
	if !ok {
		return true
	}
	return q.IsZero()
}

// riskNote builds a "; "-joined explanation of the practical risk posed by the
// missing settings, ordered most-severe first.
func riskNote(f PodFinding) string {
	notes := make([]string, 0, 4)

	if f.MissingMemoryLimit {
		notes = append(notes, "no memory limit: at risk of OOMKill without bound")
	}
	if f.MissingCPULimit {
		notes = append(notes, "no CPU limit: can starve other pods on a noisy node")
	}
	if f.MissingMemoryRequest {
		notes = append(notes, "no memory request: scheduler can overcommit the node")
	}
	if f.MissingCPURequest {
		notes = append(notes, "no CPU request: scheduler can overcommit the node")
	}

	return strings.Join(notes, "; ")
}
