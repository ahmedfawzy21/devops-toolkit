package aws

import (
	"strings"
	"testing"
)

func TestClassifyRuntime(t *testing.T) {
	tests := []struct {
		runtime     string
		wantFlagged bool
		wantNote    string // substring expected in the note when flagged
	}{
		{runtime: "python3.6", wantFlagged: true, wantNote: "deprecated"},
		{runtime: "nodejs12.x", wantFlagged: true, wantNote: "deprecated"},
		{runtime: "java8", wantFlagged: true, wantNote: "deprecated"},
		{runtime: "dotnetcore2.1", wantFlagged: true, wantNote: "deprecated"},
		{runtime: "ruby2.5", wantFlagged: true, wantNote: "deprecated"},
		{runtime: "go1.x", wantFlagged: true, wantNote: "EOL-announced"},
		{runtime: "python3.12", wantFlagged: false},
		{runtime: "nodejs20.x", wantFlagged: false},
		{runtime: "provided.al2", wantFlagged: false},
	}

	for _, tt := range tests {
		t.Run(tt.runtime, func(t *testing.T) {
			flagged, note := classifyRuntime(tt.runtime)
			if flagged != tt.wantFlagged {
				t.Fatalf("classifyRuntime(%q) flagged = %v, want %v", tt.runtime, flagged, tt.wantFlagged)
			}
			if tt.wantFlagged && !strings.Contains(note, tt.wantNote) {
				t.Errorf("classifyRuntime(%q) note = %q, want substring %q", tt.runtime, note, tt.wantNote)
			}
			if !tt.wantFlagged && note != "" {
				t.Errorf("classifyRuntime(%q) note = %q, want empty", tt.runtime, note)
			}
		})
	}
}

func TestLambdaMonthlyCost(t *testing.T) {
	// 1,000,000 invocations/month, 0.1s each, 512MB (0.5GB):
	// 1_000_000 * 0.1 * 0.5 * 0.0000166667 = 0.83333...
	got := lambdaMonthlyCost(1_000_000, 0.1, 0.5)
	want := 1_000_000.0 * 0.1 * 0.5 * lambdaGBSecondRate
	if diff := got - want; diff < -1e-9 || diff > 1e-9 {
		t.Errorf("lambdaMonthlyCost = %v, want %v", got, want)
	}

	// Zero invocations => zero cost.
	if got := lambdaMonthlyCost(0, 0.15, 1.0); got != 0 {
		t.Errorf("lambdaMonthlyCost with zero invocations = %v, want 0", got)
	}
}

func TestIsOverprovisioned(t *testing.T) {
	tests := []struct {
		name             string
		memoryMB         int32
		avgDurationMs    float64
		dailyInvocations float64
		want             bool
	}{
		{name: "big memory, short, rare -> flag", memoryMB: 1024, avgDurationMs: 50, dailyInvocations: 100, want: true},
		{name: "exactly 512MB boundary flagged", memoryMB: 512, avgDurationMs: 199, dailyInvocations: 999, want: true},
		{name: "below memory floor -> skip", memoryMB: 256, avgDurationMs: 50, dailyInvocations: 100, want: false},
		{name: "duration too long -> skip", memoryMB: 1024, avgDurationMs: 200, dailyInvocations: 100, want: false},
		{name: "too many invocations -> skip", memoryMB: 1024, avgDurationMs: 50, dailyInvocations: 1000, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOverprovisioned(tt.memoryMB, tt.avgDurationMs, tt.dailyInvocations); got != tt.want {
				t.Errorf("isOverprovisioned(%d, %v, %v) = %v, want %v",
					tt.memoryMB, tt.avgDurationMs, tt.dailyInvocations, got, tt.want)
			}
		})
	}
}

func TestRecommendedMemory(t *testing.T) {
	tests := []struct {
		in   int32
		want int32
	}{
		{in: 1024, want: 512},
		{in: 512, want: 256},
		{in: 256, want: 128},
		{in: 128, want: 128}, // never below the floor
		{in: 192, want: 128}, // 96 -> clamped to 128
	}

	for _, tt := range tests {
		if got := recommendedMemory(tt.in); got != tt.want {
			t.Errorf("recommendedMemory(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
