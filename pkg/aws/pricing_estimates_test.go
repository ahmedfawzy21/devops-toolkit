package aws

import "testing"

func TestEC2OnDemandHourlyCoverage(t *testing.T) {
	required := []string{
		"t3.micro", "t3.small", "t3.medium", "t3.large",
		"m5.large", "m5.xlarge", "m5.2xlarge",
		"c5.large", "c5.xlarge",
		"r5.large", "r5.xlarge",
	}

	for _, it := range required {
		if _, ok := EC2OnDemandHourly[it]; !ok {
			t.Errorf("missing On-Demand rate for %s", it)
		}
	}
}

func TestEstimateRICost(t *testing.T) {
	tests := []struct {
		name         string
		instanceType string
		term         string
		want         float64
	}{
		{
			// 0.096 * (1 - 0.35) = 0.0624
			name:         "m5.large 1yr no-upfront discount",
			instanceType: "m5.large",
			term:         "1yr",
			want:         0.0624,
		},
		{
			name:         "ONE_YEAR alias",
			instanceType: "m5.large",
			term:         "ONE_YEAR",
			want:         0.0624,
		},
		{
			name:         "unknown term falls back to on-demand",
			instanceType: "m5.large",
			term:         "3yr",
			want:         0.096,
		},
		{
			name:         "unknown instance type returns zero",
			instanceType: "x1.32xlarge",
			term:         "1yr",
			want:         0.0,
		},
	}

	tolerance := 0.0001
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EstimateRICost(tt.instanceType, tt.term)
			diff := got - tt.want
			if diff < -tolerance || diff > tolerance {
				t.Errorf("EstimateRICost(%q, %q) = %v, want %v", tt.instanceType, tt.term, got, tt.want)
			}
		})
	}
}

func TestMonthlyFromHourly(t *testing.T) {
	tests := []struct {
		name   string
		hourly float64
		want   float64
	}{
		{name: "m5.large on-demand", hourly: 0.096, want: 70.08},
		{name: "zero", hourly: 0.0, want: 0.0},
	}

	tolerance := 0.0001
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MonthlyFromHourly(tt.hourly)
			diff := got - tt.want
			if diff < -tolerance || diff > tolerance {
				t.Errorf("MonthlyFromHourly(%v) = %v, want %v", tt.hourly, got, tt.want)
			}
		})
	}
}
