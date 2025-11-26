package k8s

import (
	"testing"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestAnalyzePDB(t *testing.T) {
	tests := []struct {
		name           string
		pdb            policyv1.PodDisruptionBudget
		expectedStatus string
		expectedEmoji  string
	}{
		{
			name: "Healthy PDB - disruptions allowed",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "healthy-pdb",
					Namespace: "production",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 2},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     3,
					DesiredHealthy:     2,
					DisruptionsAllowed: 1,
					ExpectedPods:       3,
				},
			},
			expectedStatus: "healthy",
			expectedEmoji:  "🟢",
		},
		{
			name: "At-risk PDB - zero disruptions allowed",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "at-risk-pdb",
					Namespace: "production",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.String, StrVal: "80%"},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     2,
					DesiredHealthy:     2,
					DisruptionsAllowed: 0,
					ExpectedPods:       2,
				},
			},
			expectedStatus: "at-risk",
			expectedEmoji:  "🟡",
		},
		{
			name: "Critical PDB - zero disruptions and unhealthy pods",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "critical-pdb",
					Namespace: "production",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 3},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     2,
					DesiredHealthy:     3,
					DisruptionsAllowed: 0,
					ExpectedPods:       3,
				},
			},
			expectedStatus: "critical",
			expectedEmoji:  "🔴",
		},
		{
			name: "No pods - PDB with no matching pods",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-pods-pdb",
					Namespace: "staging",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     0,
					DesiredHealthy:     1,
					DisruptionsAllowed: 0,
					ExpectedPods:       0,
				},
			},
			expectedStatus: "no-pods",
			expectedEmoji:  "⚪",
		},
		{
			name: "At-risk - unhealthy pods but some disruptions allowed",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unhealthy-pdb",
					Namespace: "production",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 3},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     4,
					DesiredHealthy:     5,
					DisruptionsAllowed: 1,
					ExpectedPods:       5,
				},
			},
			expectedStatus: "at-risk",
			expectedEmoji:  "🟡",
		},
		{
			name: "Healthy PDB with MaxUnavailable",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "maxunavail-pdb",
					Namespace: "production",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     3,
					DesiredHealthy:     2,
					DisruptionsAllowed: 1,
					ExpectedPods:       3,
				},
			},
			expectedStatus: "healthy",
			expectedEmoji:  "🟢",
		},
		{
			name: "Healthy PDB with percentage MinAvailable",
			pdb: policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "percent-pdb",
					Namespace: "production",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.String, StrVal: "50%"},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     4,
					DesiredHealthy:     2,
					DisruptionsAllowed: 2,
					ExpectedPods:       4,
				},
			},
			expectedStatus: "healthy",
			expectedEmoji:  "🟢",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzePDB(tt.pdb)

			if result.Status != tt.expectedStatus {
				t.Errorf("Status = %q, expected %q", result.Status, tt.expectedStatus)
			}

			if result.Name != tt.pdb.Name {
				t.Errorf("Name = %q, expected %q", result.Name, tt.pdb.Name)
			}

			if result.Namespace != tt.pdb.Namespace {
				t.Errorf("Namespace = %q, expected %q", result.Namespace, tt.pdb.Namespace)
			}

			if result.CurrentHealthy != tt.pdb.Status.CurrentHealthy {
				t.Errorf("CurrentHealthy = %d, expected %d",
					result.CurrentHealthy, tt.pdb.Status.CurrentHealthy)
			}

			if result.DisruptionsAllowed != tt.pdb.Status.DisruptionsAllowed {
				t.Errorf("DisruptionsAllowed = %d, expected %d",
					result.DisruptionsAllowed, tt.pdb.Status.DisruptionsAllowed)
			}

			emoji := result.GetStatusEmoji()
			if emoji != tt.expectedEmoji {
				t.Errorf("Emoji = %q, expected %q", emoji, tt.expectedEmoji)
			}
		})
	}
}

func TestPDBGetColorCode(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected string
	}{
		{
			name:     "Healthy - green color",
			status:   "healthy",
			expected: "\033[32m",
		},
		{
			name:     "At-risk - yellow color",
			status:   "at-risk",
			expected: "\033[33m",
		},
		{
			name:     "Critical - red color",
			status:   "critical",
			expected: "\033[31m",
		},
		{
			name:     "No-pods - gray color",
			status:   "no-pods",
			expected: "\033[90m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdbInfo := PDBInfo{Status: tt.status}
			result := pdbInfo.GetColorCode()
			if result != tt.expected {
				t.Errorf("GetColorCode() for status %q = %q, expected %q",
					tt.status, result, tt.expected)
			}
		})
	}
}

func TestPDBGetStatusEmoji(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected string
	}{
		{"Healthy", "healthy", "🟢"},
		{"At-risk", "at-risk", "🟡"},
		{"Critical", "critical", "🔴"},
		{"No-pods", "no-pods", "⚪"},
		{"Unknown", "unknown", "❓"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdbInfo := PDBInfo{Status: tt.status}
			result := pdbInfo.GetStatusEmoji()
			if result != tt.expected {
				t.Errorf("GetStatusEmoji() for status %q = %q, expected %q",
					tt.status, result, tt.expected)
			}
		})
	}
}

func TestPDBGetStatusDisplay(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected string
	}{
		{"Healthy display", "healthy", "🟢 healthy"},
		{"At-risk display", "at-risk", "🟡 at-risk"},
		{"Critical display", "critical", "🔴 critical"},
		{"No-pods display", "no-pods", "⚪ no-pods"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdbInfo := PDBInfo{Status: tt.status}
			result := pdbInfo.GetStatusDisplay()
			if result != tt.expected {
				t.Errorf("GetStatusDisplay() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestFormatMinAvailable(t *testing.T) {
	tests := []struct {
		name           string
		minAvailable   string
		maxUnavailable string
		expected       string
	}{
		{
			name:           "MinAvailable set",
			minAvailable:   "2",
			maxUnavailable: "-",
			expected:       "2",
		},
		{
			name:           "MinAvailable percentage",
			minAvailable:   "80%",
			maxUnavailable: "-",
			expected:       "80%",
		},
		{
			name:           "MaxUnavailable set",
			minAvailable:   "-",
			maxUnavailable: "1",
			expected:       "max-unavail:1",
		},
		{
			name:           "Neither set",
			minAvailable:   "-",
			maxUnavailable: "-",
			expected:       "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdbInfo := PDBInfo{
				MinAvailable:   tt.minAvailable,
				MaxUnavailable: tt.maxUnavailable,
			}
			result := pdbInfo.FormatMinAvailable()
			if result != tt.expected {
				t.Errorf("FormatMinAvailable() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestPDBStatusDetermination(t *testing.T) {
	tests := []struct {
		name               string
		currentHealthy     int32
		desiredHealthy     int32
		disruptionsAllowed int32
		expectedPods       int32
		expectedStatus     string
		expectedMessage    string
	}{
		{
			name:               "Healthy - all pods running, disruptions allowed",
			currentHealthy:     5,
			desiredHealthy:     3,
			disruptionsAllowed: 2,
			expectedPods:       5,
			expectedStatus:     "healthy",
			expectedMessage:    "2 disruption(s) allowed",
		},
		{
			name:               "At-risk - zero disruptions allowed",
			currentHealthy:     3,
			desiredHealthy:     3,
			disruptionsAllowed: 0,
			expectedPods:       3,
			expectedStatus:     "at-risk",
			expectedMessage:    "Zero disruptions allowed",
		},
		{
			name:               "Critical - zero disruptions and unhealthy",
			currentHealthy:     2,
			desiredHealthy:     3,
			disruptionsAllowed: 0,
			expectedPods:       3,
			expectedStatus:     "critical",
			expectedMessage:    "Zero disruptions allowed and unhealthy pods",
		},
		{
			name:               "No-pods - no expected pods",
			currentHealthy:     0,
			desiredHealthy:     1,
			disruptionsAllowed: 0,
			expectedPods:       0,
			expectedStatus:     "no-pods",
			expectedMessage:    "No matching pods found",
		},
		{
			name:               "No-pods - zero current healthy",
			currentHealthy:     0,
			desiredHealthy:     2,
			disruptionsAllowed: 0,
			expectedPods:       2,
			expectedStatus:     "no-pods",
			expectedMessage:    "No matching pods found",
		},
		{
			name:               "At-risk - unhealthy pods with disruptions allowed",
			currentHealthy:     2,
			desiredHealthy:     3,
			disruptionsAllowed: 1,
			expectedPods:       3,
			expectedStatus:     "at-risk",
			expectedMessage:    "Unhealthy pods: 2/3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdb := policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pdb",
					Namespace: "default",
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MinAvailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
				Status: policyv1.PodDisruptionBudgetStatus{
					CurrentHealthy:     tt.currentHealthy,
					DesiredHealthy:     tt.desiredHealthy,
					DisruptionsAllowed: tt.disruptionsAllowed,
					ExpectedPods:       tt.expectedPods,
				},
			}

			result := analyzePDB(pdb)

			if result.Status != tt.expectedStatus {
				t.Errorf("Status = %q, expected %q", result.Status, tt.expectedStatus)
			}

			if result.StatusMessage != tt.expectedMessage {
				t.Errorf("StatusMessage = %q, expected %q", result.StatusMessage, tt.expectedMessage)
			}
		})
	}
}
