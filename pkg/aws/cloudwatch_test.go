package aws

import "testing"

func TestCalculateLogStorageCost(t *testing.T) {
	tests := []struct {
		name        string
		storedBytes int64
		want        float64
	}{
		{
			name:        "1GB standard storage",
			storedBytes: 1024 * 1024 * 1024,
			want:        0.03,
		},
		{
			name:        "100GB standard storage",
			storedBytes: 100 * 1024 * 1024 * 1024,
			want:        3.0,
		},
		{
			name:        "zero bytes",
			storedBytes: 0,
			want:        0.0,
		},
	}

	tolerance := 0.0001
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateLogStorageCost(tt.storedBytes)
			diff := got - tt.want
			if diff < -tolerance || diff > tolerance {
				t.Errorf("calculateLogStorageCost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogGroupFinding(t *testing.T) {
	f := LogGroupFinding{
		Name:              "/aws/lambda/my-fn",
		RetentionDays:     -1,
		StoredBytes:       2 * 1024 * 1024 * 1024,
		LastIngestionDays: -1,
		MonthlyCost:       0.06,
		Reason:            "no retention policy set; logs are stored indefinitely",
	}

	if f.RetentionDays != -1 {
		t.Errorf("RetentionDays = %v, want -1 (no policy)", f.RetentionDays)
	}

	if f.Name == "" {
		t.Error("Name should not be empty")
	}
}
