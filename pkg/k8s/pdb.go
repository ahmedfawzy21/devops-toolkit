package k8s

import (
	"context"
	"fmt"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PDBInfo holds information about a PodDisruptionBudget
type PDBInfo struct {
	Name                string
	Namespace           string
	MinAvailable        string
	MaxUnavailable      string
	CurrentHealthy      int32
	DesiredHealthy      int32
	DisruptionsAllowed  int32
	ExpectedPods        int32
	Status              string // "healthy", "at-risk", "critical", "no-pods"
	StatusMessage       string
}

// PDBResults holds the results of PDB checking
type PDBResults struct {
	PDBs           []PDBInfo
	TotalScanned   int
	HealthyCount   int
	AtRiskCount    int
	CriticalCount  int
	NoPodsCount    int
}

// CheckPDBStatus checks the status of all PodDisruptionBudgets
func (h *HealthChecker) CheckPDBStatus(ctx context.Context, namespace string) (*PDBResults, error) {
	// List all PDBs in the specified namespace(s)
	pdbs, err := h.clientset.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list PDBs: %w", err)
	}

	results := &PDBResults{
		PDBs: make([]PDBInfo, 0, len(pdbs.Items)),
	}

	for _, pdb := range pdbs.Items {
		results.TotalScanned++

		pdbInfo := analyzePDB(pdb)

		// Count by status
		switch pdbInfo.Status {
		case "healthy":
			results.HealthyCount++
		case "at-risk":
			results.AtRiskCount++
		case "critical":
			results.CriticalCount++
		case "no-pods":
			results.NoPodsCount++
		}

		results.PDBs = append(results.PDBs, pdbInfo)
	}

	return results, nil
}

// analyzePDB analyzes a single PDB and determines its health status
func analyzePDB(pdb policyv1.PodDisruptionBudget) PDBInfo {
	info := PDBInfo{
		Name:               pdb.Name,
		Namespace:          pdb.Namespace,
		CurrentHealthy:     pdb.Status.CurrentHealthy,
		DesiredHealthy:     pdb.Status.DesiredHealthy,
		DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
		ExpectedPods:       pdb.Status.ExpectedPods,
	}

	// Get MinAvailable or MaxUnavailable
	if pdb.Spec.MinAvailable != nil {
		info.MinAvailable = pdb.Spec.MinAvailable.String()
	} else {
		info.MinAvailable = "-"
	}

	if pdb.Spec.MaxUnavailable != nil {
		info.MaxUnavailable = pdb.Spec.MaxUnavailable.String()
	} else {
		info.MaxUnavailable = "-"
	}

	// Determine status
	if info.ExpectedPods == 0 || info.CurrentHealthy == 0 {
		info.Status = "no-pods"
		info.StatusMessage = "No matching pods found"
	} else if info.DisruptionsAllowed == 0 {
		if info.CurrentHealthy < info.DesiredHealthy {
			info.Status = "critical"
			info.StatusMessage = "Zero disruptions allowed and unhealthy pods"
		} else {
			info.Status = "at-risk"
			info.StatusMessage = "Zero disruptions allowed"
		}
	} else if info.CurrentHealthy < info.DesiredHealthy {
		info.Status = "at-risk"
		info.StatusMessage = fmt.Sprintf("Unhealthy pods: %d/%d", info.CurrentHealthy, info.DesiredHealthy)
	} else {
		info.Status = "healthy"
		info.StatusMessage = fmt.Sprintf("%d disruption(s) allowed", info.DisruptionsAllowed)
	}

	return info
}

// GetColorCode returns the color code for terminal output based on status
func (p *PDBInfo) GetColorCode() string {
	switch p.Status {
	case "critical":
		return "\033[31m" // Red
	case "at-risk":
		return "\033[33m" // Yellow
	case "no-pods":
		return "\033[90m" // Gray
	default:
		return "\033[32m" // Green
	}
}

// GetStatusEmoji returns an emoji for the status
func (p *PDBInfo) GetStatusEmoji() string {
	switch p.Status {
	case "healthy":
		return "🟢"
	case "at-risk":
		return "🟡"
	case "critical":
		return "🔴"
	case "no-pods":
		return "⚪"
	default:
		return "❓"
	}
}

// GetStatusDisplay returns a formatted status string with emoji
func (p *PDBInfo) GetStatusDisplay() string {
	return fmt.Sprintf("%s %s", p.GetStatusEmoji(), p.Status)
}

// FormatMinAvailable returns a display-friendly format for MinAvailable
func (p *PDBInfo) FormatMinAvailable() string {
	if p.MinAvailable != "-" {
		return p.MinAvailable
	}
	if p.MaxUnavailable != "-" {
		return fmt.Sprintf("max-unavail:%s", p.MaxUnavailable)
	}
	return "-"
}
