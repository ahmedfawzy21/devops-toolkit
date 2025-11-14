package reporter

import (
	"testing"
)

func TestNewReporter(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   string
	}{
		{
			name:   "table format",
			format: "table",
			want:   "table",
		},
		{
			name:   "json format",
			format: "json",
			want:   "json",
		},
		{
			name:   "csv format",
			format: "csv",
			want:   "csv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter := NewReporter(tt.format)
			if reporter == nil {
				t.Fatal("NewReporter() returned nil")
			}
			if reporter.format != tt.want {
				t.Errorf("NewReporter() format = %v, want %v", reporter.format, tt.want)
			}
		})
	}
}

func TestReporterFormats(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		expectedType *Reporter
	}{
		{
			name:         "table reporter",
			format:       "table",
			expectedType: &Reporter{format: "table"},
		},
		{
			name:         "json reporter",
			format:       "json",
			expectedType: &Reporter{format: "json"},
		},
		{
			name:         "csv reporter",
			format:       "csv",
			expectedType: &Reporter{format: "csv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter := NewReporter(tt.format)

			if reporter == nil {
				t.Fatalf("NewReporter(%s) returned nil", tt.format)
			}

			if reporter.format != tt.expectedType.format {
				t.Errorf("NewReporter(%s).format = %v, want %v",
					tt.format, reporter.format, tt.expectedType.format)
			}

			// Verify reporter is created correctly and has the expected format
			switch tt.format {
			case "table":
				if reporter.format != "table" {
					t.Errorf("Expected table reporter, got format: %s", reporter.format)
				}
			case "json":
				if reporter.format != "json" {
					t.Errorf("Expected json reporter, got format: %s", reporter.format)
				}
			case "csv":
				if reporter.format != "csv" {
					t.Errorf("Expected csv reporter, got format: %s", reporter.format)
				}
			}
		})
	}
}
