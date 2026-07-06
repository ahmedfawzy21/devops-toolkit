package eks

// Results aggregates the findings from every EKS-layer auditor in this package
// (nodes, pods, namespaces, and node groups), mirroring aws.AuditResults /
// k8s.HealthResults.
type Results struct {
	UnderutilizedNodes    []NodeFinding
	PodsWithoutLimits     []PodFinding
	NamespaceCosts        []NamespaceCost
	NodeGroupRatios       []NodeGroupRatio
	TotalPotentialSavings float64
}

// CalculateSavings rolls up the dollar-denominated findings into
// TotalPotentialSavings: per-node rightsizing savings plus per-node-group Spot
// rebalancing savings. Namespace costs are an allocation of existing spend (not
// savings) and pod findings carry no dollar figure, so neither contributes.
func (r *Results) CalculateSavings() {
	total := 0.0

	for _, node := range r.UnderutilizedNodes {
		total += instanceRightsizeSavings(node.InstanceType)
	}

	for _, ng := range r.NodeGroupRatios {
		total += ng.EstimatedMonthlySavingsIfRebalanced
	}

	r.TotalPotentialSavings = total
}
