package aws

import (
	"testing"
)

func TestEstimateRDSCost(t *testing.T) {
	tests := []struct {
		name          string
		instanceClass string
		want          float64
	}{
		{
			name:          "db.t3.micro",
			instanceClass: "db.t3.micro",
			want:          15.00,
		},
		{
			name:          "db.t3.small",
			instanceClass: "db.t3.small",
			want:          30.00,
		},
		{
			name:          "db.m5.large",
			instanceClass: "db.m5.large",
			want:          145.00,
		},
		{
			name:          "db.r5.xlarge (unknown)",
			instanceClass: "db.r5.xlarge",
			want:          100.00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateRDSCost(tt.instanceClass)
			if got != tt.want {
				t.Errorf("estimateRDSCost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnderutilizedRDSInstance(t *testing.T) {
	instance := UnderutilizedRDSInstance{
		InstanceID:        "mydb-instance-1",
		InstanceClass:     "db.t3.micro",
		Engine:            "postgres",
		AvgCPUUtilization: 3.5,
		MonthlyCost:       15.00,
	}

	if instance.InstanceID == "" {
		t.Error("InstanceID should not be empty")
	}

	if instance.InstanceID != "mydb-instance-1" {
		t.Errorf("InstanceID = %v, want mydb-instance-1", instance.InstanceID)
	}

	if instance.InstanceClass != "db.t3.micro" {
		t.Errorf("InstanceClass = %v, want db.t3.micro", instance.InstanceClass)
	}

	if instance.Engine != "postgres" {
		t.Errorf("Engine = %v, want postgres", instance.Engine)
	}

	if instance.AvgCPUUtilization != 3.5 {
		t.Errorf("AvgCPUUtilization = %v, want 3.5", instance.AvgCPUUtilization)
	}

	if instance.MonthlyCost != 15.00 {
		t.Errorf("MonthlyCost = %v, want 15.00", instance.MonthlyCost)
	}
}
