package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
	"github.com/ahmedfawzy/devops-toolkit/pkg/k8s"
	"github.com/olekukonko/tablewriter"
)

type Reporter struct {
	format string
}

func NewReporter(format string) *Reporter {
	return &Reporter{format: format}
}

func (r *Reporter) RenderAuditResults(results *aws.AuditResults) error {
	switch r.format {
	case "json":
		return r.renderAuditJSON(results)
	case "table":
		return r.renderAuditTable(results)
	case "csv":
		return r.renderAuditCSV(results)
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

func (r *Reporter) RenderHealthResults(results *k8s.HealthResults) error {
	switch r.format {
	case "json":
		return r.renderHealthJSON(results)
	case "table":
		return r.renderHealthTable(results)
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

func (r *Reporter) RenderCostResults(results *aws.CostResults) error {
	switch r.format {
	case "json":
		return r.renderCostJSON(results)
	case "table":
		return r.renderCostTable(results)
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

func (r *Reporter) renderAuditJSON(results *aws.AuditResults) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func (r *Reporter) renderAuditTable(results *aws.AuditResults) error {
	// Unattached volumes
	if len(results.UnattachedVolumes) > 0 {
		fmt.Println("📦 Unattached EBS Volumes")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Volume ID", "Size (GB)", "Type", "AZ", "Age (days)", "Monthly Cost"})
		table.SetBorder(false)

		for _, vol := range results.UnattachedVolumes {
			age := int(time.Since(vol.CreateTime).Hours() / 24)
			table.Append([]string{
				vol.VolumeID,
				fmt.Sprintf("%d", vol.Size),
				vol.VolumeType,
				vol.AvailabilityZone,
				fmt.Sprintf("%d", age),
				fmt.Sprintf("$%.2f", vol.MonthlyCost),
			})
		}
		table.Render()
		fmt.Println()
	}

	// Underutilized instances
	if len(results.UnderutilizedInstances) > 0 {
		fmt.Println("💻 Underutilized EC2 Instances (< 5% CPU)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Instance ID", "Type", "Avg CPU %", "State", "Age (days)", "Monthly Cost"})
		table.SetBorder(false)

		for _, inst := range results.UnderutilizedInstances {
			age := int(time.Since(inst.LaunchTime).Hours() / 24)
			table.Append([]string{
				inst.InstanceID,
				inst.InstanceType,
				fmt.Sprintf("%.2f%%", inst.AvgCPUUtilization),
				inst.State,
				fmt.Sprintf("%d", age),
				fmt.Sprintf("$%.2f", inst.MonthlyCost),
			})
		}
		table.Render()
		fmt.Println()
	}

	// Orphaned snapshots
	if len(results.OrphanedSnapshots) > 0 {
		fmt.Println("📸 Orphaned EBS Snapshots")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Snapshot ID", "Size (GB)", "Age (days)", "Monthly Cost"})
		table.SetBorder(false)

		for _, snap := range results.OrphanedSnapshots {
			age := int(time.Since(snap.CreateTime).Hours() / 24)
			table.Append([]string{
				snap.SnapshotID,
				fmt.Sprintf("%d", snap.Size),
				fmt.Sprintf("%d", age),
				fmt.Sprintf("$%.2f", snap.MonthlyCost),
			})
		}
		table.Render()
		fmt.Println()
	}

	// Unused Elastic IPs
	if len(results.UnusedElasticIPs) > 0 {
		fmt.Println("🌐 Unused Elastic IPs")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Allocation ID", "Public IP", "Monthly Cost"})
		table.SetBorder(false)

		for _, eip := range results.UnusedElasticIPs {
			table.Append([]string{
				eip.AllocationID,
				eip.PublicIP,
				fmt.Sprintf("$%.2f", eip.MonthlyCost),
			})
		}
		table.Render()
		fmt.Println()
	}

	// Underutilized RDS instances
	if len(results.UnderutilizedRDSInstances) > 0 {
		fmt.Println("🗄️  Underutilized RDS Instances (< 10% CPU)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Instance ID", "Instance Class", "Engine", "Avg CPU %", "Monthly Cost"})
		table.SetBorder(false)

		for _, rds := range results.UnderutilizedRDSInstances {
			table.Append([]string{
				rds.InstanceID,
				rds.InstanceClass,
				rds.Engine,
				fmt.Sprintf("%.2f%%", rds.AvgCPUUtilization),
				fmt.Sprintf("$%.2f", rds.MonthlyCost),
			})
		}
		table.Render()
		fmt.Println()
	}

	// Summary
	fmt.Println("💰 Potential Monthly Savings")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("Total: $%.2f\n\n", results.TotalPotentialSavings)

	if results.TotalPotentialSavings > 0 {
		fmt.Printf("💡 Annual savings potential: $%.2f\n", results.TotalPotentialSavings*12)
	}

	return nil
}

func (r *Reporter) renderAuditCSV(results *aws.AuditResults) error {
	writer := csv.NewWriter(os.Stdout)

	// Write header
	if err := writer.Write([]string{"ResourceType", "ResourceID", "Details", "MonthlyCost"}); err != nil {
		return err
	}

	// Unattached volumes
	for _, vol := range results.UnattachedVolumes {
		details := fmt.Sprintf("Size: %dGB Type: %s", vol.Size, vol.VolumeType)
		cost := fmt.Sprintf("%.2f", vol.MonthlyCost)
		if err := writer.Write([]string{"EBS Volume", vol.VolumeID, details, cost}); err != nil {
			return err
		}
	}

	// Underutilized EC2 instances
	for _, inst := range results.UnderutilizedInstances {
		details := fmt.Sprintf("Type: %s CPU: %.2f%%", inst.InstanceType, inst.AvgCPUUtilization)
		cost := fmt.Sprintf("%.2f", inst.MonthlyCost)
		if err := writer.Write([]string{"EC2 Instance", inst.InstanceID, details, cost}); err != nil {
			return err
		}
	}

	// Underutilized RDS instances
	for _, rds := range results.UnderutilizedRDSInstances {
		details := fmt.Sprintf("Class: %s Engine: %s CPU: %.2f%%", rds.InstanceClass, rds.Engine, rds.AvgCPUUtilization)
		cost := fmt.Sprintf("%.2f", rds.MonthlyCost)
		if err := writer.Write([]string{"RDS Instance", rds.InstanceID, details, cost}); err != nil {
			return err
		}
	}

	// Orphaned snapshots
	for _, snap := range results.OrphanedSnapshots {
		details := fmt.Sprintf("Size: %dGB", snap.Size)
		cost := fmt.Sprintf("%.2f", snap.MonthlyCost)
		if err := writer.Write([]string{"EBS Snapshot", snap.SnapshotID, details, cost}); err != nil {
			return err
		}
	}

	// Unused Elastic IPs
	for _, eip := range results.UnusedElasticIPs {
		details := fmt.Sprintf("IP: %s", eip.PublicIP)
		cost := fmt.Sprintf("%.2f", eip.MonthlyCost)
		if err := writer.Write([]string{"Elastic IP", eip.AllocationID, details, cost}); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}

func (r *Reporter) renderHealthJSON(results *k8s.HealthResults) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func (r *Reporter) renderHealthTable(results *k8s.HealthResults) error {
	// Pods
	if len(results.Pods) > 0 {
		fmt.Println("🔵 Pods Status")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Namespace", "Name", "Ready", "Status", "Restarts", "Age"})
		table.SetBorder(false)

		for _, pod := range results.Pods {
			age := formatDuration(pod.Age)
			table.Append([]string{
				pod.Namespace,
				pod.Name,
				pod.Ready,
				pod.Status,
				fmt.Sprintf("%d", pod.Restarts),
				age,
			})
		}
		table.Render()
		fmt.Println()
	}

	// Deployments
	if len(results.Deployments) > 0 {
		fmt.Println("📦 Deployments Status")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Namespace", "Name", "Ready", "Up-to-date", "Available", "Age"})
		table.SetBorder(false)

		for _, dep := range results.Deployments {
			age := formatDuration(dep.Age)
			table.Append([]string{
				dep.Namespace,
				dep.Name,
				dep.Ready,
				fmt.Sprintf("%d", dep.UpToDate),
				fmt.Sprintf("%d", dep.Available),
				age,
			})
		}
		table.Render()
		fmt.Println()
	}

	// Nodes
	if len(results.Nodes) > 0 {
		fmt.Println("🖥️  Nodes Status")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Name", "Status", "Roles", "Version", "Age"})
		table.SetBorder(false)

		for _, node := range results.Nodes {
			age := formatDuration(node.Age)
			table.Append([]string{
				node.Name,
				node.Status,
				node.Roles,
				node.KubeletVersion,
				age,
			})
		}
		table.Render()
		fmt.Println()
	}

	// Warning events
	if len(results.WarningEvents) > 0 {
		fmt.Println("⚠️  Recent Warning Events (Last Hour)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Namespace", "Kind", "Name", "Reason", "Count"})
		table.SetBorder(false)
		table.SetAutoWrapText(false)

		for _, event := range results.WarningEvents {
			table.Append([]string{
				event.Namespace,
				event.Kind,
				event.Name,
				event.Reason,
				fmt.Sprintf("%d", event.Count),
			})
		}
		table.Render()
		fmt.Println()
	} else {
		fmt.Println("✅ No warning events in the last hour")
	}

	return nil
}

func (r *Reporter) renderCostJSON(results *aws.CostResults) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func (r *Reporter) renderCostTable(results *aws.CostResults) error {
	// Summary
	fmt.Printf("📊 Cost Report (%s to %s)\n", 
		results.StartDate.Format("2006-01-02"),
		results.EndDate.Format("2006-01-02"))
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("Total Cost: $%.2f %s\n\n", results.TotalCost, results.Currency)

	// Cost breakdown
	if len(results.Items) > 0 {
		fmt.Printf("💵 Cost Breakdown by %s\n", results.GroupBy)
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{results.GroupBy, "Cost", "% of Total"})
		table.SetBorder(false)

		for _, item := range results.Items {
			percentage := (item.Amount / results.TotalCost) * 100
			table.Append([]string{
				item.Name,
				fmt.Sprintf("$%.2f", item.Amount),
				fmt.Sprintf("%.1f%%", percentage),
			})
		}
		table.Render()
		fmt.Println()
	}

	// Daily trend
	if len(results.DailyTrend) > 0 {
		fmt.Println("📈 Daily Spending Trend")
		fmt.Println("─────────────────────────────────────────────────────────────")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Date", "Daily Cost"})
		table.SetBorder(false)

		for _, daily := range results.DailyTrend {
			table.Append([]string{
				daily.Date,
				fmt.Sprintf("$%.2f", daily.Amount),
			})
		}
		table.Render()
		fmt.Println()
	}

	return nil
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	
	if days > 0 {
		return fmt.Sprintf("%dd%dh", days, hours)
	}
	return fmt.Sprintf("%dh", hours)
}
