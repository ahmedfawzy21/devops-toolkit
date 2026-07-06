package eks

import "testing"

func TestVersionBelowMinimum(t *testing.T) {
	tests := []struct {
		name    string
		current string
		minimum string
		want    bool
	}{
		{name: "1.27 is below 1.28", current: "1.27", minimum: "1.28", want: true},
		{name: "1.28 exactly is not below", current: "1.28", minimum: "1.28", want: false},
		{name: "1.29 is not below", current: "1.29", minimum: "1.28", want: false},
		{name: "1.21 well below", current: "1.21", minimum: "1.28", want: true},
		{name: "1.30 above", current: "1.30", minimum: "1.28", want: false},
		{name: "leading v tolerated", current: "v1.27", minimum: "1.28", want: true},
		{name: "patch suffix tolerated", current: "1.27.3", minimum: "1.28", want: true},
		{name: "eks build suffix tolerated", current: "1.29+eks", minimum: "1.28", want: false},
		{name: "major bump not below", current: "2.0", minimum: "1.28", want: false},
		{name: "unparseable current not flagged", current: "unknown", minimum: "1.28", want: false},
		{name: "empty current not flagged", current: "", minimum: "1.28", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionBelowMinimum(tt.current, tt.minimum); got != tt.want {
				t.Errorf("versionBelowMinimum(%q, %q) = %v, want %v", tt.current, tt.minimum, got, tt.want)
			}
		})
	}
}

func TestParseK8sVersion(t *testing.T) {
	tests := []struct {
		in        string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{in: "1.28", wantMajor: 1, wantMinor: 28, wantOK: true},
		{in: "v1.27", wantMajor: 1, wantMinor: 27, wantOK: true},
		{in: "1.29.4", wantMajor: 1, wantMinor: 29, wantOK: true},
		{in: "1.30+eks", wantMajor: 1, wantMinor: 30, wantOK: true},
		{in: "1", wantOK: false},
		{in: "garbage", wantOK: false},
		{in: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			major, minor, ok := parseK8sVersion(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("parseK8sVersion(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
			}
			if ok && (major != tt.wantMajor || minor != tt.wantMinor) {
				t.Errorf("parseK8sVersion(%q) = %d.%d, want %d.%d", tt.in, major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestEvaluateRootRisk(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	b := func(v bool) *bool { return &v }

	tests := []struct {
		name         string
		uid          *int64
		nonRoot      *bool
		wantFlagged  bool
		wantSeverity string
	}{
		{name: "uid 0 is critical", uid: i64(0), wantFlagged: true, wantSeverity: severityCritical},
		{name: "non-zero uid is safe", uid: i64(1000), wantFlagged: false},
		{name: "RunAsNonRoot false is critical", nonRoot: b(false), wantFlagged: true, wantSeverity: severityCritical},
		{name: "RunAsNonRoot true is safe", nonRoot: b(true), wantFlagged: false},
		{name: "nothing set is a warning", wantFlagged: true, wantSeverity: severityWarning},
		{name: "uid takes precedence over nonRoot", uid: i64(1000), nonRoot: b(false), wantFlagged: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagged, severity, note := evaluateRootRisk(tt.uid, tt.nonRoot)
			if flagged != tt.wantFlagged {
				t.Fatalf("evaluateRootRisk flagged = %v, want %v", flagged, tt.wantFlagged)
			}
			if tt.wantFlagged {
				if severity != tt.wantSeverity {
					t.Errorf("severity = %q, want %q", severity, tt.wantSeverity)
				}
				if note == "" {
					t.Error("expected a non-empty note for a flagged finding")
				}
			}
		})
	}
}
