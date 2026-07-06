package eks

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func TestOnDemandPercent(t *testing.T) {
	tests := []struct {
		onDemand, total int
		want            float64
	}{
		{8, 10, 80},
		{0, 10, 0},
		{10, 10, 100},
		{0, 0, 0}, // division-by-zero guard
	}

	for _, tt := range tests {
		if got := onDemandPercent(tt.onDemand, tt.total); !almostEqual(got, tt.want) {
			t.Errorf("onDemandPercent(%d, %d) = %v, want %v", tt.onDemand, tt.total, got, tt.want)
		}
	}
}

func TestEstimateRebalanceSavings(t *testing.T) {
	// Above threshold: 80% On-Demand, 8 nodes, $100/node.
	// nodesToMove = 0.30 * 8 = 2.4; savings = 2.4 * 100 * 0.60 = 144.
	if got := estimateRebalanceSavings(8, 80, 100); !almostEqual(got, 144.0) {
		t.Errorf("estimateRebalanceSavings(8, 80, 100) = %v, want 144", got)
	}

	// Below threshold -> 0.
	if got := estimateRebalanceSavings(5, 50, 100); got != 0 {
		t.Errorf("estimateRebalanceSavings below threshold = %v, want 0", got)
	}

	// Exactly at the threshold is not "above" -> 0.
	if got := estimateRebalanceSavings(7, 70, 100); got != 0 {
		t.Errorf("estimateRebalanceSavings at threshold = %v, want 0", got)
	}

	// Unknown per-node cost (0) -> 0 savings even above threshold.
	if got := estimateRebalanceSavings(8, 80, 0); got != 0 {
		t.Errorf("estimateRebalanceSavings with zero node cost = %v, want 0", got)
	}
}

func TestFirstInstanceType(t *testing.T) {
	if got := firstInstanceType([]string{"m5.large", "m5.xlarge"}); got != "m5.large" {
		t.Errorf("firstInstanceType = %q, want m5.large", got)
	}
	if got := firstInstanceType(nil); got != "" {
		t.Errorf("firstInstanceType(nil) = %q, want \"\"", got)
	}
	if got := firstInstanceType([]string{}); got != "" {
		t.Errorf("firstInstanceType(empty) = %q, want \"\"", got)
	}
}

func TestDesiredSize(t *testing.T) {
	ng := &ekstypes.Nodegroup{
		ScalingConfig: &ekstypes.NodegroupScalingConfig{
			DesiredSize: aws.Int32(3),
		},
	}
	if got := desiredSize(ng); got != 3 {
		t.Errorf("desiredSize = %d, want 3", got)
	}

	// Nil ScalingConfig -> 0.
	if got := desiredSize(&ekstypes.Nodegroup{}); got != 0 {
		t.Errorf("desiredSize(nil scaling) = %d, want 0", got)
	}
}
