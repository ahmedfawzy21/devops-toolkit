package eks

import (
	"math"
	"testing"
)

const floatTolerance = 0.0001

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= floatTolerance
}

func TestNextSmallerInstance(t *testing.T) {
	tests := []struct {
		instanceType string
		want         string
		wantOK       bool
	}{
		{"m5.2xlarge", "m5.xlarge", true},
		{"m5.xlarge", "m5.large", true},
		{"t3.large", "t3.medium", true},
		{"t3.micro", "", false}, // smallest in family
		{"m5.large", "", false}, // smallest modeled in family
		{"x1.32xlarge", "", false},
	}

	for _, tt := range tests {
		got, ok := nextSmallerInstance(tt.instanceType)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("nextSmallerInstance(%q) = (%q, %v), want (%q, %v)", tt.instanceType, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestNodeMonthlyCost(t *testing.T) {
	// 0.384 * 730 = 280.32
	if got := nodeMonthlyCost("m5.2xlarge"); !almostEqual(got, 280.32) {
		t.Errorf("nodeMonthlyCost(m5.2xlarge) = %v, want 280.32", got)
	}
	// Unknown instance type -> 0
	if got := nodeMonthlyCost("x1.32xlarge"); got != 0 {
		t.Errorf("nodeMonthlyCost(unknown) = %v, want 0", got)
	}
	// Empty -> 0
	if got := nodeMonthlyCost(""); got != 0 {
		t.Errorf("nodeMonthlyCost(\"\") = %v, want 0", got)
	}
}

func TestInstanceRightsizeSavings(t *testing.T) {
	// m5.2xlarge (280.32) - m5.xlarge (140.16) = 140.16
	if got := instanceRightsizeSavings("m5.2xlarge"); !almostEqual(got, 140.16) {
		t.Errorf("instanceRightsizeSavings(m5.2xlarge) = %v, want 140.16", got)
	}
	// No smaller size -> 0
	if got := instanceRightsizeSavings("t3.micro"); got != 0 {
		t.Errorf("instanceRightsizeSavings(t3.micro) = %v, want 0", got)
	}
	// Unknown -> 0
	if got := instanceRightsizeSavings("x1.32xlarge"); got != 0 {
		t.Errorf("instanceRightsizeSavings(unknown) = %v, want 0", got)
	}
}

func TestRecommendSmallerInstance(t *testing.T) {
	if got := recommendSmallerInstance(""); got != "instance type unknown; review utilization manually" {
		t.Errorf("recommendSmallerInstance(\"\") = %q", got)
	}

	got := recommendSmallerInstance("m5.2xlarge")
	want := "downsize m5.2xlarge -> m5.xlarge (~$140.16/mo saved)"
	if got != want {
		t.Errorf("recommendSmallerInstance(m5.2xlarge) = %q, want %q", got, want)
	}

	// Smallest in family falls through to the consolidation hint.
	got = recommendSmallerInstance("t3.micro")
	want = "t3.micro is already the smallest known size in its family; consider consolidating workloads"
	if got != want {
		t.Errorf("recommendSmallerInstance(t3.micro) = %q, want %q", got, want)
	}
}

func TestNodeInstanceType(t *testing.T) {
	// Stable label preferred.
	labels := map[string]string{
		"node.kubernetes.io/instance-type": "m5.large",
		"beta.kubernetes.io/instance-type": "m5.xlarge",
	}
	if got := nodeInstanceType(labels); got != "m5.large" {
		t.Errorf("nodeInstanceType stable = %q, want m5.large", got)
	}

	// Falls back to beta label.
	if got := nodeInstanceType(map[string]string{"beta.kubernetes.io/instance-type": "c5.large"}); got != "c5.large" {
		t.Errorf("nodeInstanceType beta = %q, want c5.large", got)
	}

	// Neither present.
	if got := nodeInstanceType(map[string]string{}); got != "" {
		t.Errorf("nodeInstanceType empty = %q, want \"\"", got)
	}
}

func TestResultsCalculateSavings(t *testing.T) {
	r := &Results{
		UnderutilizedNodes: []NodeFinding{
			{InstanceType: "m5.2xlarge"}, // 140.16 rightsize savings
			{InstanceType: "t3.micro"},   // 0 (smallest)
		},
		NodeGroupRatios: []NodeGroupRatio{
			{EstimatedMonthlySavingsIfRebalanced: 50.0},
			{EstimatedMonthlySavingsIfRebalanced: 0.0},
		},
		// Namespace costs and pod findings must not contribute.
		NamespaceCosts:    []NamespaceCost{{MonthlyCost: 999.0}},
		PodsWithoutLimits: []PodFinding{{PodName: "x"}},
	}

	r.CalculateSavings()

	if !almostEqual(r.TotalPotentialSavings, 190.16) {
		t.Errorf("TotalPotentialSavings = %v, want 190.16", r.TotalPotentialSavings)
	}
}
