package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestIsUnderutilized(t *testing.T) {
	tests := []struct {
		name        string
		provisioned int64
		consumed    float64
		want        bool
	}{
		{name: "10% utilization flagged", provisioned: 100, consumed: 10, want: true},
		{name: "exactly 20% not flagged", provisioned: 100, consumed: 20, want: false},
		{name: "50% utilization not flagged", provisioned: 100, consumed: 50, want: false},
		{name: "zero provisioned not flagged", provisioned: 0, consumed: 0, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnderutilized(tt.provisioned, tt.consumed)
			if got != tt.want {
				t.Errorf("isUnderutilized(%d, %v) = %v, want %v", tt.provisioned, tt.consumed, got, tt.want)
			}
		})
	}
}

func TestCalculateDynamoDBWaste(t *testing.T) {
	tests := []struct {
		name        string
		provRCU     int64
		provWCU     int64
		consumedRCU float64
		consumedWCU float64
		want        float64
	}{
		{
			// 90 wasted RCU * 0.00065 * 730 = 42.705
			name:        "underused reads only",
			provRCU:     100,
			provWCU:     0,
			consumedRCU: 10,
			consumedWCU: 0,
			want:        42.705,
		},
		{
			// zero consumed: full 100 RCU + 100 WCU wasted = 94.9
			name:        "zero consumed wastes full provisioned",
			provRCU:     100,
			provWCU:     100,
			consumedRCU: 0,
			consumedWCU: 0,
			want:        94.9,
		},
		{
			// reads: 90*0.00065*730, writes: 90*0.00065*730 = 85.41
			name:        "underused reads and writes",
			provRCU:     100,
			provWCU:     100,
			consumedRCU: 10,
			consumedWCU: 10,
			want:        85.41,
		},
		{
			// consumption above provisioned never produces negative waste
			name:        "no waste when fully used",
			provRCU:     100,
			provWCU:     100,
			consumedRCU: 200,
			consumedWCU: 200,
			want:        0.0,
		},
	}

	tolerance := 0.01
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateDynamoDBWaste(tt.provRCU, tt.provWCU, tt.consumedRCU, tt.consumedWCU)
			diff := got - tt.want
			if diff < -tolerance || diff > tolerance {
				t.Errorf("calculateDynamoDBWaste() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsProvisionedTable(t *testing.T) {
	tests := []struct {
		name  string
		table *dynamodbtypes.TableDescription
		want  bool
	}{
		{
			name: "nil BillingModeSummary with provisioned throughput defaults to provisioned",
			table: &dynamodbtypes.TableDescription{
				ProvisionedThroughput: &dynamodbtypes.ProvisionedThroughputDescription{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			want: true,
		},
		{
			name:  "nil BillingModeSummary and nil throughput is not provisioned",
			table: &dynamodbtypes.TableDescription{},
			want:  false,
		},
		{
			name: "explicit PROVISIONED billing mode",
			table: &dynamodbtypes.TableDescription{
				BillingModeSummary: &dynamodbtypes.BillingModeSummary{
					BillingMode: dynamodbtypes.BillingModeProvisioned,
				},
			},
			want: true,
		},
		{
			name: "PAY_PER_REQUEST billing mode is not provisioned",
			table: &dynamodbtypes.TableDescription{
				BillingModeSummary: &dynamodbtypes.BillingModeSummary{
					BillingMode: dynamodbtypes.BillingModePayPerRequest,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProvisionedTable(tt.table)
			if got != tt.want {
				t.Errorf("isProvisionedTable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDynamoDBFinding(t *testing.T) {
	f := DynamoDBFinding{
		TableName: "users",
		Issue:     "no_pitr",
	}

	if f.Issue != "no_pitr" {
		t.Errorf("Issue = %v, want no_pitr", f.Issue)
	}
}
