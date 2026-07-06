package eks

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestAnalyzeContainerResources_AllMissing(t *testing.T) {
	c := corev1.Container{Name: "app"} // no Resources set at all

	f := analyzeContainerResources("default", "pod-1", c)

	if !f.MissingCPURequest || !f.MissingCPULimit || !f.MissingMemoryRequest || !f.MissingMemoryLimit {
		t.Fatalf("expected all four resource settings missing, got %+v", f)
	}
	if !f.hasMissingResource() {
		t.Errorf("hasMissingResource() = false, want true")
	}
	// Risk note should mention both the OOMKill and CPU-starvation risks.
	if !strings.Contains(f.RiskNote, "OOMKill") || !strings.Contains(f.RiskNote, "starve") {
		t.Errorf("RiskNote missing expected risks: %q", f.RiskNote)
	}
}

func TestAnalyzeContainerResources_Partial(t *testing.T) {
	// Has a CPU request only; everything else missing.
	c := corev1.Container{
		Name: "app",
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("100m"),
			},
		},
	}

	f := analyzeContainerResources("ns", "pod-2", c)

	if f.MissingCPURequest {
		t.Errorf("MissingCPURequest = true, want false (request was set)")
	}
	if !f.MissingCPULimit || !f.MissingMemoryRequest || !f.MissingMemoryLimit {
		t.Errorf("expected CPU limit + both memory settings missing, got %+v", f)
	}
}

func TestAnalyzeContainerResources_FullySpecified(t *testing.T) {
	c := corev1.Container{
		Name: "app",
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		},
	}

	f := analyzeContainerResources("ns", "pod-3", c)

	if f.hasMissingResource() {
		t.Errorf("expected nothing missing, got %+v", f)
	}
	if f.RiskNote != "" {
		t.Errorf("RiskNote = %q, want empty", f.RiskNote)
	}
}

func TestIsResourceMissing(t *testing.T) {
	// nil list -> missing
	if !isResourceMissing(nil, corev1.ResourceCPU) {
		t.Errorf("nil list should be missing")
	}
	// absent key -> missing
	list := corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")}
	if !isResourceMissing(list, corev1.ResourceCPU) {
		t.Errorf("absent key should be missing")
	}
	// explicit zero quantity -> missing
	zero := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("0")}
	if !isResourceMissing(zero, corev1.ResourceCPU) {
		t.Errorf("zero quantity should be treated as missing")
	}
	// present non-zero -> not missing
	if isResourceMissing(list, corev1.ResourceMemory) {
		t.Errorf("present non-zero should not be missing")
	}
}
