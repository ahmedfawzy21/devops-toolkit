package eks

import "testing"

func TestAllocateNamespaceCosts_Proportional(t *testing.T) {
	reservations := []namespaceReservation{
		{Namespace: "small", CPUReservedPercent: 25, MemoryReservedPercent: 25}, // weight 50
		{Namespace: "big", CPUReservedPercent: 50, MemoryReservedPercent: 50},   // weight 100
	}

	got := allocateNamespaceCosts(reservations, 150.0)

	if len(got) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(got))
	}

	// Sorted descending by cost: "big" first.
	if got[0].Namespace != "big" || got[1].Namespace != "small" {
		t.Fatalf("expected descending sort [big, small], got [%s, %s]", got[0].Namespace, got[1].Namespace)
	}

	// Total weight = 150. big share = 100/150 -> $100; small = 50/150 -> $50.
	if !almostEqual(got[0].MonthlyCost, 100.0) {
		t.Errorf("big MonthlyCost = %v, want 100", got[0].MonthlyCost)
	}
	if !almostEqual(got[1].MonthlyCost, 50.0) {
		t.Errorf("small MonthlyCost = %v, want 50", got[1].MonthlyCost)
	}
	if !almostEqual(got[0].PercentOfClusterCost, 100.0/150.0*100) {
		t.Errorf("big PercentOfClusterCost = %v", got[0].PercentOfClusterCost)
	}

	// Costs should sum back to the cluster total.
	if !almostEqual(got[0].MonthlyCost+got[1].MonthlyCost, 150.0) {
		t.Errorf("namespace costs do not sum to cluster total")
	}
}

func TestAllocateNamespaceCosts_ZeroWeightNoNaN(t *testing.T) {
	reservations := []namespaceReservation{
		{Namespace: "a", CPUReservedPercent: 0, MemoryReservedPercent: 0},
		{Namespace: "b", CPUReservedPercent: 0, MemoryReservedPercent: 0},
	}

	got := allocateNamespaceCosts(reservations, 100.0)

	for _, c := range got {
		if c.MonthlyCost != 0 {
			t.Errorf("namespace %s: MonthlyCost = %v, want 0 when total weight is 0", c.Namespace, c.MonthlyCost)
		}
		if c.PercentOfClusterCost != 0 {
			t.Errorf("namespace %s: PercentOfClusterCost = %v, want 0", c.Namespace, c.PercentOfClusterCost)
		}
	}
}

func TestAllocateNamespaceCosts_Empty(t *testing.T) {
	got := allocateNamespaceCosts(nil, 100.0)
	if got == nil {
		t.Errorf("expected non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d", len(got))
	}
}
