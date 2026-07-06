package aws

import "testing"

func TestReservationRecommendation(t *testing.T) {
	r := ReservationRecommendation{
		InstanceType:                 "m5.large",
		InstanceCount:                3,
		EstimatedMonthlySavings:      120.50,
		EstimatedMonthlyOnDemandCost: 264.00,
		UpfrontCost:                  0.0,
	}

	if r.InstanceType != "m5.large" {
		t.Errorf("InstanceType = %v, want m5.large", r.InstanceType)
	}
	if r.InstanceCount != 3 {
		t.Errorf("InstanceCount = %v, want 3", r.InstanceCount)
	}
	if r.EstimatedMonthlySavings != 120.50 {
		t.Errorf("EstimatedMonthlySavings = %v, want 120.50", r.EstimatedMonthlySavings)
	}
}

func TestSavingsPlanRecommendation(t *testing.T) {
	r := SavingsPlanRecommendation{
		HourlyCommitment:           "0.50",
		EstimatedMonthlySavings:    85.0,
		EstimatedSavingsPercentage: 22.5,
	}

	if r.HourlyCommitment != "0.50" {
		t.Errorf("HourlyCommitment = %v, want 0.50", r.HourlyCommitment)
	}
	if r.EstimatedSavingsPercentage != 22.5 {
		t.Errorf("EstimatedSavingsPercentage = %v, want 22.5", r.EstimatedSavingsPercentage)
	}
}

// parseFloat is reused by the savings analyzer to convert Cost Explorer's
// string-typed amounts; verify the conversions it relies on.
func TestParseFloatForSavings(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{in: "120.50", want: 120.50},
		{in: "0", want: 0.0},
		{in: "", want: 0.0},
	}

	for _, tt := range tests {
		got := parseFloat(tt.in)
		if got != tt.want {
			t.Errorf("parseFloat(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
