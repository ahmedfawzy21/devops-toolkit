package aws

import (
	"testing"
	"time"
)

func TestCalculateEBSCost(t *testing.T) {
	tests := []struct {
		name       string
		sizeGB     int32
		volumeType string
		want       float64
	}{
		{
			name:       "gp3 100GB",
			sizeGB:     100,
			volumeType: "gp3",
			want:       8.0,
		},
		{
			name:       "gp2 50GB",
			sizeGB:     50,
			volumeType: "gp2",
			want:       5.0,
		},
		{
			name:       "io1 200GB",
			sizeGB:     200,
			volumeType: "io1",
			want:       25.0,
		},
		{
			name:       "st1 1000GB",
			sizeGB:     1000,
			volumeType: "st1",
			want:       45.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateEBSCost(tt.sizeGB, tt.volumeType)
			if got != tt.want {
				t.Errorf("calculateEBSCost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateSnapshotCost(t *testing.T) {
	tests := []struct {
		name   string
		sizeGB int32
		want   float64
	}{
		{
			name:   "100GB snapshot",
			sizeGB: 100,
			want:   5.0,
		},
		{
			name:   "500GB snapshot",
			sizeGB: 500,
			want:   25.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateSnapshotCost(tt.sizeGB)
			if got != tt.want {
				t.Errorf("calculateSnapshotCost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEstimateEC2Cost(t *testing.T) {
	tests := []struct {
		name         string
		instanceType string
		want         float64
	}{
		{
			name:         "t3.micro",
			instanceType: "t3.micro",
			want:         9.0,
		},
		{
			name:         "m5.large",
			instanceType: "m5.large",
			want:         88.0,
		},
		{
			name:         "unknown type defaults",
			instanceType: "r6g.16xlarge",
			want:         100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateEC2Cost(tt.instanceType)
			if got != tt.want {
				t.Errorf("estimateEC2Cost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditResultsCalculateSavings(t *testing.T) {
	results := &AuditResults{
		UnattachedVolumes: []UnattachedVolume{
			{
				VolumeID:    "vol-123",
				Size:        100,
				VolumeType:  "gp3",
				MonthlyCost: 8.0,
			},
			{
				VolumeID:    "vol-456",
				Size:        50,
				VolumeType:  "gp2",
				MonthlyCost: 5.0,
			},
		},
		UnderutilizedInstances: []UnderutilizedInstance{
			{
				InstanceID:   "i-123",
				InstanceType: "t3.micro",
				MonthlyCost:  9.0,
			},
		},
		UnderutilizedRDSInstances: []UnderutilizedRDSInstance{
			{
				InstanceID:        "rds-db1",
				InstanceClass:     "db.t3.micro",
				Engine:            "postgres",
				AvgCPUUtilization: 5.0,
				MonthlyCost:       15.0,
			},
			{
				InstanceID:        "rds-db2",
				InstanceClass:     "db.t3.small",
				Engine:            "mysql",
				AvgCPUUtilization: 3.0,
				MonthlyCost:       30.0,
			},
		},
		OrphanedSnapshots: []OrphanedSnapshot{
			{
				SnapshotID:  "snap-123",
				Size:        100,
				MonthlyCost: 5.0,
			},
		},
		UnusedElasticIPs: []UnusedElasticIP{
			{
				AllocationID: "eipalloc-123",
				PublicIP:     "54.123.45.67",
				MonthlyCost:  3.60,
			},
			{
				AllocationID: "eipalloc-456",
				PublicIP:     "54.123.45.68",
				MonthlyCost:  3.60,
			},
		},
	}

	results.CalculateSavings()

	// 8.0 + 5.0 (volumes) + 9.0 (ec2) + 15.0 + 30.0 (rds) + 5.0 (snapshots) + 3.60 + 3.60 (eips) = 79.20
	expectedTotal := 79.20
	tolerance := 0.01 // Allow small floating point differences
	diff := results.TotalPotentialSavings - expectedTotal
	if diff < -tolerance || diff > tolerance {
		t.Errorf("CalculateSavings() = %v, want %v (within %.2f)", results.TotalPotentialSavings, expectedTotal, tolerance)
	}
}

func TestUnattachedVolume(t *testing.T) {
	vol := UnattachedVolume{
		VolumeID:         "vol-123abc",
		Size:             100,
		VolumeType:       "gp3",
		AvailabilityZone: "us-east-1a",
		CreateTime:       time.Now().Add(-30 * 24 * time.Hour),
		MonthlyCost:      8.0,
	}

	if vol.VolumeID == "" {
		t.Error("VolumeID should not be empty")
	}

	if vol.Size != 100 {
		t.Errorf("Size = %v, want 100", vol.Size)
	}

	if vol.MonthlyCost != 8.0 {
		t.Errorf("MonthlyCost = %v, want 8.0", vol.MonthlyCost)
	}
}
