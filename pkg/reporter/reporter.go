package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
	"github.com/ahmedfawzy/devops-toolkit/pkg/eks"
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

	// Log groups
	if len(results.LogGroupFindings) > 0 {
		renderLogGroupTable(results.LogGroupFindings)
	}

	// DynamoDB tables
	if len(results.DynamoDBFindings) > 0 {
		renderDynamoDBTable(results.DynamoDBFindings)
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

	// CloudWatch log groups
	for _, lg := range results.LogGroupFindings {
		details := fmt.Sprintf("Stored: %.2fGB %s", bytesToGB(lg.StoredBytes), lg.Reason)
		cost := fmt.Sprintf("%.2f", lg.MonthlyCost)
		if err := writer.Write([]string{"CloudWatch Log Group", lg.Name, details, cost}); err != nil {
			return err
		}
	}

	// DynamoDB tables
	for _, ddb := range results.DynamoDBFindings {
		details := fmt.Sprintf("Issue: %s", ddb.Issue)
		cost := fmt.Sprintf("%.2f", ddb.MonthlyCost)
		if err := writer.Write([]string{"DynamoDB Table", ddb.TableName, details, cost}); err != nil {
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

// RenderLogGroupResults renders CloudWatch log group findings split into
// "without retention" and "dead" sets.
func (r *Reporter) RenderLogGroupResults(withoutRetention, dead []aws.LogGroupFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			WithoutRetention []aws.LogGroupFinding `json:"withoutRetention"`
			Dead             []aws.LogGroupFinding `json:"dead"`
		}{withoutRetention, dead})
	case "table":
		fmt.Println("📋 Log Groups Without Retention Policy")
		fmt.Println("─────────────────────────────────────────────────────────────")
		if len(withoutRetention) == 0 {
			fmt.Println("  No log groups without retention found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Log Group", "Stored (GB)", "Monthly Cost", "Reason"})
			table.SetBorder(false)
			for _, lg := range withoutRetention {
				table.Append([]string{
					lg.Name,
					fmt.Sprintf("%.2f", bytesToGB(lg.StoredBytes)),
					fmt.Sprintf("$%.2f", lg.MonthlyCost),
					lg.Reason,
				})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("🪵 Dead Log Groups (no incoming events in 30 days)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		if len(dead) == 0 {
			fmt.Println("  No dead log groups found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Log Group", "Retention", "Stored (GB)", "Last Ingestion (days)", "Monthly Cost"})
			table.SetBorder(false)
			for _, lg := range dead {
				table.Append([]string{
					lg.Name,
					retentionLabel(lg.RetentionDays),
					fmt.Sprintf("%.2f", bytesToGB(lg.StoredBytes)),
					lastIngestionLabel(lg.LastIngestionDays),
					fmt.Sprintf("$%.2f", lg.MonthlyCost),
				})
			}
			table.Render()
		}
		fmt.Println()

		total := sumLogGroupCost(withoutRetention, dead)
		fmt.Println("💰 Potential Monthly Savings")
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Printf("Total: $%.2f\n\n", total)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderDynamoDBResults renders DynamoDB findings split into "without PITR" and
// "overprovisioned" sets.
func (r *Reporter) RenderDynamoDBResults(withoutPITR, overprovisioned []aws.DynamoDBFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			WithoutPITR     []aws.DynamoDBFinding `json:"withoutPitr"`
			Overprovisioned []aws.DynamoDBFinding `json:"overprovisioned"`
		}{withoutPITR, overprovisioned})
	case "table":
		fmt.Println("🔒 DynamoDB Tables Without Point-in-Time Recovery")
		fmt.Println("─────────────────────────────────────────────────────────────")
		if len(withoutPITR) == 0 {
			fmt.Println("  No tables missing PITR found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Table", "Issue"})
			table.SetBorder(false)
			for _, t := range withoutPITR {
				table.Append([]string{t.TableName, t.Issue})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("📊 Overprovisioned DynamoDB Tables (< 20% utilization)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		if len(overprovisioned) == 0 {
			fmt.Println("  No overprovisioned tables found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Table", "Prov RCU", "Cons RCU", "Prov WCU", "Cons WCU", "Monthly Waste"})
			table.SetBorder(false)
			for _, t := range overprovisioned {
				table.Append([]string{
					t.TableName,
					fmt.Sprintf("%d", t.ProvisionedRCU),
					fmt.Sprintf("%.2f", t.ConsumedRCU),
					fmt.Sprintf("%d", t.ProvisionedWCU),
					fmt.Sprintf("%.2f", t.ConsumedWCU),
					fmt.Sprintf("$%.2f", t.MonthlyCost),
				})
			}
			table.Render()
		}
		fmt.Println()

		total := 0.0
		for _, t := range overprovisioned {
			total += t.MonthlyCost
		}
		fmt.Println("💰 Potential Monthly Savings")
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Printf("Total: $%.2f\n\n", total)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderSavingsResults renders Cost Explorer reservation and savings plan
// recommendations.
func (r *Reporter) RenderSavingsResults(reservations []aws.ReservationRecommendation, savingsPlans []aws.SavingsPlanRecommendation) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			ReservationRecommendations []aws.ReservationRecommendation `json:"reservationRecommendations"`
			SavingsPlanRecommendations []aws.SavingsPlanRecommendation `json:"savingsPlanRecommendations"`
		}{reservations, savingsPlans})
	case "table":
		if len(reservations) == 0 && len(savingsPlans) == 0 {
			fmt.Println("ℹ️  Not enough usage history (requires 30+ days) for savings recommendations yet")
			return nil
		}

		fmt.Println("📉 Reserved Instance Recommendations (1yr, No Upfront)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		if len(reservations) == 0 {
			fmt.Println("  No reserved instance recommendations ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Instance Type", "Count", "Est Monthly Savings", "Est Monthly On-Demand", "Upfront Cost"})
			table.SetBorder(false)
			for _, rec := range reservations {
				table.Append([]string{
					rec.InstanceType,
					fmt.Sprintf("%d", rec.InstanceCount),
					fmt.Sprintf("$%.2f", rec.EstimatedMonthlySavings),
					fmt.Sprintf("$%.2f", rec.EstimatedMonthlyOnDemandCost),
					fmt.Sprintf("$%.2f", rec.UpfrontCost),
				})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("💸 Savings Plan Recommendations (Compute, 1yr, No Upfront)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		if len(savingsPlans) == 0 {
			fmt.Println("  No savings plan recommendations ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Hourly Commitment", "Est Monthly Savings", "Est Savings %"})
			table.SetBorder(false)
			for _, sp := range savingsPlans {
				table.Append([]string{
					sp.HourlyCommitment,
					fmt.Sprintf("$%.2f", sp.EstimatedMonthlySavings),
					fmt.Sprintf("%.1f%%", sp.EstimatedSavingsPercentage),
				})
			}
			table.Render()
		}
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

func renderLogGroupTable(findings []aws.LogGroupFinding) {
	fmt.Println("📋 CloudWatch Log Groups")
	fmt.Println("─────────────────────────────────────────────────────────────")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Log Group", "Retention", "Stored (GB)", "Last Ingestion (days)", "Monthly Cost", "Reason"})
	table.SetBorder(false)
	for _, lg := range findings {
		table.Append([]string{
			lg.Name,
			retentionLabel(lg.RetentionDays),
			fmt.Sprintf("%.2f", bytesToGB(lg.StoredBytes)),
			lastIngestionLabel(lg.LastIngestionDays),
			fmt.Sprintf("$%.2f", lg.MonthlyCost),
			lg.Reason,
		})
	}
	table.Render()
	fmt.Println()
}

func renderDynamoDBTable(findings []aws.DynamoDBFinding) {
	fmt.Println("🗂️  DynamoDB Tables")
	fmt.Println("─────────────────────────────────────────────────────────────")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Table", "Issue", "Prov RCU", "Cons RCU", "Prov WCU", "Cons WCU", "Monthly Cost"})
	table.SetBorder(false)
	for _, t := range findings {
		table.Append([]string{
			t.TableName,
			t.Issue,
			fmt.Sprintf("%d", t.ProvisionedRCU),
			fmt.Sprintf("%.2f", t.ConsumedRCU),
			fmt.Sprintf("%d", t.ProvisionedWCU),
			fmt.Sprintf("%.2f", t.ConsumedWCU),
			fmt.Sprintf("$%.2f", t.MonthlyCost),
		})
	}
	table.Render()
	fmt.Println()
}

func jsonEncode(v interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func bytesToGB(b int64) float64 {
	return float64(b) / (1024 * 1024 * 1024)
}

func retentionLabel(days int32) string {
	if days < 0 {
		return "none"
	}
	return fmt.Sprintf("%d", days)
}

func lastIngestionLabel(days int) string {
	if days < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d", days)
}

// sumLogGroupCost totals monthly cost across both finding sets, counting each
// log group only once when it appears in both.
func sumLogGroupCost(sets ...[]aws.LogGroupFinding) float64 {
	seen := make(map[string]float64)
	for _, set := range sets {
		for _, lg := range set {
			if existing, ok := seen[lg.Name]; !ok || lg.MonthlyCost > existing {
				seen[lg.Name] = lg.MonthlyCost
			}
		}
	}
	total := 0.0
	for _, cost := range seen {
		total += cost
	}
	return total
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24

	if days > 0 {
		return fmt.Sprintf("%dd%dh", days, hours)
	}
	return fmt.Sprintf("%dh", hours)
}

// eksDivider matches the section divider used throughout the table renderers.
const eksDivider = "─────────────────────────────────────────────────────────────"

// RenderEKSNodeResults renders underutilized EKS node findings.
func (r *Reporter) RenderEKSNodeResults(findings []eks.NodeFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(findings)
	case "table":
		renderEKSNodeTable(findings)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderEKSPodResults renders pods missing resource requests/limits.
func (r *Reporter) RenderEKSPodResults(findings []eks.PodFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(findings)
	case "table":
		renderEKSPodTable(findings)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderEKSNamespaceResults renders the per-namespace cost breakdown.
func (r *Reporter) RenderEKSNamespaceResults(costs []eks.NamespaceCost) error {
	switch r.format {
	case "json":
		return jsonEncode(costs)
	case "table":
		renderEKSNamespaceTable(costs)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderEKSNodeGroupResults renders node group Spot/On-Demand ratios.
func (r *Reporter) RenderEKSNodeGroupResults(ratios []eks.NodeGroupRatio) error {
	switch r.format {
	case "json":
		return jsonEncode(ratios)
	case "table":
		renderEKSNodeGroupTable(ratios)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderEKSResults renders the combined EKS audit: every populated section plus
// the rolled-up potential savings.
func (r *Reporter) RenderEKSResults(results *eks.Results) error {
	switch r.format {
	case "json":
		return jsonEncode(results)
	case "table":
		renderEKSNodeTable(results.UnderutilizedNodes)
		renderEKSPodTable(results.PodsWithoutLimits)
		renderEKSNamespaceTable(results.NamespaceCosts)
		renderEKSNodeGroupTable(results.NodeGroupRatios)

		fmt.Println("💰 Potential Monthly Savings (node rightsizing + Spot rebalancing)")
		fmt.Println(eksDivider)
		fmt.Printf("Total: $%.2f\n\n", results.TotalPotentialSavings)
		if results.TotalPotentialSavings > 0 {
			fmt.Printf("💡 Annual savings potential: $%.2f\n", results.TotalPotentialSavings*12)
		}
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

func renderEKSNodeTable(findings []eks.NodeFinding) {
	fmt.Println("🖥️  Underutilized EKS Nodes (CPU & memory < 30%)")
	fmt.Println(eksDivider)
	if len(findings) == 0 {
		fmt.Println("  No underutilized nodes found ✅")
		fmt.Println()
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Node", "Instance Type", "Avg CPU %", "Avg Mem %", "Monthly Cost", "Recommendation"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	for _, n := range findings {
		table.Append([]string{
			n.NodeName,
			n.InstanceType,
			fmt.Sprintf("%.1f%%", n.AvgCPUPercent),
			fmt.Sprintf("%.1f%%", n.AvgMemoryPercent),
			fmt.Sprintf("$%.2f", n.MonthlyCost),
			n.Recommendation,
		})
	}
	table.Render()
	fmt.Println()
}

func renderEKSPodTable(findings []eks.PodFinding) {
	fmt.Println("📦 Pods Missing Resource Requests/Limits")
	fmt.Println(eksDivider)
	if len(findings) == 0 {
		fmt.Println("  No pods missing requests/limits found ✅")
		fmt.Println()
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Namespace", "Pod", "Container", "Missing", "Risk"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	for _, p := range findings {
		table.Append([]string{
			p.Namespace,
			p.PodName,
			p.ContainerName,
			missingResourceList(p),
			p.RiskNote,
		})
	}
	table.Render()
	fmt.Println()
}

func renderEKSNamespaceTable(costs []eks.NamespaceCost) {
	fmt.Println("🏷️  Namespace Cost Breakdown (by reserved-capacity share)")
	fmt.Println(eksDivider)
	if len(costs) == 0 {
		fmt.Println("  No namespace cost data found ✅")
		fmt.Println()
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Namespace", "CPU Reserved %", "Mem Reserved %", "Monthly Cost", "% of Cluster"})
	table.SetBorder(false)
	for _, c := range costs {
		table.Append([]string{
			c.Namespace,
			fmt.Sprintf("%.1f%%", c.CPUReservedPercent),
			fmt.Sprintf("%.1f%%", c.MemoryReservedPercent),
			fmt.Sprintf("$%.2f", c.MonthlyCost),
			fmt.Sprintf("%.1f%%", c.PercentOfClusterCost),
		})
	}
	table.Render()
	fmt.Println()
}

func renderEKSNodeGroupTable(ratios []eks.NodeGroupRatio) {
	fmt.Println("⚖️  Node Group Spot/On-Demand Ratio")
	fmt.Println(eksDivider)
	if len(ratios) == 0 {
		fmt.Println("  No node groups found ✅")
		fmt.Println()
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Node Group", "Total", "On-Demand", "Spot", "On-Demand %", "Est. Savings if Rebalanced"})
	table.SetBorder(false)
	for _, ng := range ratios {
		table.Append([]string{
			ng.NodeGroupName,
			fmt.Sprintf("%d", ng.TotalNodes),
			fmt.Sprintf("%d", ng.OnDemandCount),
			fmt.Sprintf("%d", ng.SpotCount),
			fmt.Sprintf("%.1f%%", ng.OnDemandPercent),
			fmt.Sprintf("$%.2f", ng.EstimatedMonthlySavingsIfRebalanced),
		})
	}
	table.Render()
	fmt.Println()
}

// RenderIMDSResults renders EC2 instances that still allow IMDSv1.
func (r *Reporter) RenderIMDSResults(findings []aws.IMDSFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(findings)
	case "table":
		fmt.Println("🔓 EC2 Instances Allowing IMDSv1 (SSRF credential-theft risk)")
		fmt.Println(eksDivider)
		if len(findings) == 0 {
			fmt.Println("  No instances allowing IMDSv1 found ✅")
			fmt.Println()
			return nil
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Instance ID", "Name", "Type", "Http Tokens", "Remediation"})
		table.SetBorder(false)
		table.SetAutoWrapText(false)
		for _, f := range findings {
			table.Append([]string{
				f.InstanceID,
				valueOrDash(f.InstanceName),
				f.InstanceType,
				httpTokensLabel(f.HttpTokens),
				f.Remediation,
			})
		}
		table.Render()
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderLambdaResults renders the three Lambda security/cost finding sets.
func (r *Reporter) RenderLambdaResults(deprecated, publicURLs, overprovisioned []aws.LambdaFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			DeprecatedRuntimes []aws.LambdaFinding `json:"deprecatedRuntimes"`
			PublicFunctionURLs []aws.LambdaFinding `json:"publicFunctionUrls"`
			Overprovisioned    []aws.LambdaFinding `json:"overprovisioned"`
		}{deprecated, publicURLs, overprovisioned})
	case "table":
		fmt.Println("🧟 Lambda Functions with Deprecated Runtimes")
		fmt.Println(eksDivider)
		if len(deprecated) == 0 {
			fmt.Println("  No deprecated runtimes found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Function", "Runtime", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range deprecated {
				table.Append([]string{f.FunctionName, f.Runtime, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("🌐 Publicly Invocable Lambda Function URLs (AuthType NONE)")
		fmt.Println(eksDivider)
		if len(publicURLs) == 0 {
			fmt.Println("  No public function URLs found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Function", "Runtime", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range publicURLs {
				table.Append([]string{f.FunctionName, f.Runtime, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("📉 Over-provisioned Lambda Functions")
		fmt.Println(eksDivider)
		if len(overprovisioned) == 0 {
			fmt.Println("  No over-provisioned functions found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Function", "Memory (MB)", "Recommended (MB)", "Est Monthly Cost", "Note"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range overprovisioned {
				table.Append([]string{
					f.FunctionName,
					fmt.Sprintf("%d", f.MemoryMB),
					fmt.Sprintf("%d", f.RecommendedMemoryMB),
					fmt.Sprintf("$%.2f", f.MonthlyCost),
					f.RiskNote,
				})
			}
			table.Render()
		}
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderIAMResults renders the three IAM finding sets.
func (r *Reporter) RenderIAMResults(noMFA, oldKeys, overpermissioned []aws.IAMFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			UsersWithoutMFA       []aws.IAMFinding `json:"usersWithoutMfa"`
			OldAccessKeys         []aws.IAMFinding `json:"oldAccessKeys"`
			OverpermissionedRoles []aws.IAMFinding `json:"overpermissionedRoles"`
		}{noMFA, oldKeys, overpermissioned})
	case "table":
		fmt.Println("🔑 IAM Users Without MFA")
		fmt.Println(eksDivider)
		if len(noMFA) == 0 {
			fmt.Println("  No console users missing MFA found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"User", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range noMFA {
				table.Append([]string{f.ResourceName, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("🗝️  Old Active Access Keys (> 90 days)")
		fmt.Println(eksDivider)
		if len(oldKeys) == 0 {
			fmt.Println("  No old active access keys found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"User / Key", "Age (days)", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range oldKeys {
				table.Append([]string{f.ResourceName, fmt.Sprintf("%d", f.DaysSinceLastUse), f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("👑 Over-permissioned IAM Roles")
		fmt.Println(eksDivider)
		if len(overpermissioned) == 0 {
			fmt.Println("  No over-permissioned roles found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Role", "Issue", "Policy", "Last Used", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range overpermissioned {
				table.Append([]string{
					f.ResourceName,
					f.Issue,
					valueOrDash(f.PolicyName),
					lastUsedLabel(f.DaysSinceLastUse),
					f.RiskNote,
				})
			}
			table.Render()
		}
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderSecretsResults renders plaintext-secret findings. Only names/keys are
// ever printed — never the underlying secret values.
func (r *Reporter) RenderSecretsResults(ssmSecrets, lambdaEnvVars []aws.SecretFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			SSMParameters []aws.SecretFinding `json:"ssmParameters"`
			LambdaEnvVars []aws.SecretFinding `json:"lambdaEnvVars"`
		}{ssmSecrets, lambdaEnvVars})
	case "table":
		fmt.Println("🔐 Plaintext Secrets in SSM Parameter Store")
		fmt.Println(eksDivider)
		if len(ssmSecrets) == 0 {
			fmt.Println("  No plaintext SSM secrets found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Parameter Name", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range ssmSecrets {
				table.Append([]string{f.SecretKeyName, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("🔓 Potential Secrets in Lambda Environment Variables")
		fmt.Println(eksDivider)
		if len(lambdaEnvVars) == 0 {
			fmt.Println("  No suspect Lambda environment variables found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Function", "Env Var Key", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range lambdaEnvVars {
				table.Append([]string{f.ResourceName, f.SecretKeyName, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderEKSSecurityResults renders the three EKS security finding sets.
func (r *Reporter) RenderEKSSecurityResults(publicEndpoints, rootPods, outdated []eks.EKSSecurityFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(struct {
			PublicEndpointClusters []eks.EKSSecurityFinding `json:"publicEndpointClusters"`
			PodsRunningAsRoot      []eks.EKSSecurityFinding `json:"podsRunningAsRoot"`
			OutdatedClusters       []eks.EKSSecurityFinding `json:"outdatedClusters"`
		}{publicEndpoints, rootPods, outdated})
	case "table":
		fmt.Println("🌍 EKS Clusters with Public API Endpoints")
		fmt.Println(eksDivider)
		if len(publicEndpoints) == 0 {
			fmt.Println("  No fully-public cluster endpoints found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Cluster", "Severity", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range publicEndpoints {
				table.Append([]string{f.ClusterName, f.Severity, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("👤 Pods Running as Root")
		fmt.Println(eksDivider)
		if len(rootPods) == 0 {
			fmt.Println("  No pods running as root found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Namespace", "Pod", "Severity", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range rootPods {
				table.Append([]string{f.Namespace, f.PodName, f.Severity, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()

		fmt.Println("🕰️  Outdated EKS Cluster Versions")
		fmt.Println(eksDivider)
		if len(outdated) == 0 {
			fmt.Println("  No outdated cluster versions found ✅")
		} else {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Cluster", "Current", "Minimum", "Severity", "Risk"})
			table.SetBorder(false)
			table.SetAutoWrapText(false)
			for _, f := range outdated {
				table.Append([]string{f.ClusterName, f.CurrentVersion, f.MinimumVersion, f.Severity, f.RiskNote})
			}
			table.Render()
		}
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// RenderRDSSecurityResults renders RDS security findings, grouped into critical
// and warning severities. In table format the (long) remediation column is
// truncated for readability; JSON always carries the full string.
func (r *Reporter) RenderRDSSecurityResults(findings []aws.RDSSecurityFinding) error {
	switch r.format {
	case "json":
		return jsonEncode(findings)
	case "table":
		critical := make([]aws.RDSSecurityFinding, 0)
		warnings := make([]aws.RDSSecurityFinding, 0)
		instances := make(map[string]bool)
		for _, f := range findings {
			instances[f.DBInstanceIdentifier] = true
			if f.Severity == "critical" {
				critical = append(critical, f)
			} else {
				warnings = append(warnings, f)
			}
		}

		fmt.Println("🗄️  RDS Security Findings")
		fmt.Println(eksDivider)
		fmt.Println()

		renderRDSSecurityTable("🔴 Critical", critical, "  No critical RDS findings ✅")
		renderRDSSecurityTable("🟡 Warnings", warnings, "  No RDS warnings ✅")

		fmt.Printf("%d critical, %d warnings — run with --format json for full remediation details\n\n",
			len(critical), len(warnings))
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// renderRDSSecurityTable renders one severity group of RDS security findings.
func renderRDSSecurityTable(title string, findings []aws.RDSSecurityFinding, emptyMsg string) {
	fmt.Println(title)
	fmt.Println(eksDivider)
	if len(findings) == 0 {
		fmt.Println(emptyMsg)
		fmt.Println()
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"INSTANCE", "ENGINE", "VERSION", "ISSUE", "RISK", "REMEDIATION"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	for _, f := range findings {
		table.Append([]string{
			f.DBInstanceIdentifier,
			f.Engine,
			f.EngineVersion,
			f.Issue,
			f.RiskNote,
			truncate(f.Remediation, 60),
		})
	}
	table.Render()
	fmt.Println()
}

// truncate shortens s to at most maxLen runes, appending "..." when it is cut.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// valueOrDash returns "-" for an empty string, otherwise the value.
func valueOrDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// httpTokensLabel renders the IMDS HttpTokens value, showing an explicit label
// when it is unset (nil in the API).
func httpTokensLabel(httpTokens string) string {
	if httpTokens == "" {
		return "optional (unset)"
	}
	return httpTokens
}

// lastUsedLabel renders a "days since last use" value, showing "never" for the
// -1 sentinel.
func lastUsedLabel(days int) string {
	if days < 0 {
		return "never"
	}
	return fmt.Sprintf("%d days ago", days)
}

// missingResourceList builds a compact comma-separated list of the missing
// request/limit settings for a pod finding.
func missingResourceList(f eks.PodFinding) string {
	parts := make([]string, 0, 4)
	if f.MissingCPURequest {
		parts = append(parts, "cpu-request")
	}
	if f.MissingCPULimit {
		parts = append(parts, "cpu-limit")
	}
	if f.MissingMemoryRequest {
		parts = append(parts, "mem-request")
	}
	if f.MissingMemoryLimit {
		parts = append(parts, "mem-limit")
	}
	return strings.Join(parts, ", ")
}
