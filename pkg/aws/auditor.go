package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type Auditor struct {
	ec2Client        *ec2.Client
	cloudwatchClient *cloudwatch.Client
	region           string
}

type UnattachedVolume struct {
	VolumeID         string
	Size             int32
	VolumeType       string
	AvailabilityZone string
	CreateTime       time.Time
	MonthlyCost      float64
}

type UnderutilizedInstance struct {
	InstanceID       string
	InstanceType     string
	State            string
	AvgCPUUtilization float64
	MonthlyCost      float64
	LaunchTime       time.Time
}

type OrphanedSnapshot struct {
	SnapshotID  string
	Size        int32
	CreateTime  time.Time
	Description string
	MonthlyCost float64
}

type UnusedElasticIP struct {
	AllocationID string
	PublicIP     string
	MonthlyCost  float64
}

type AuditResults struct {
	UnattachedVolumes         []UnattachedVolume
	UnderutilizedInstances    []UnderutilizedInstance
	UnderutilizedRDSInstances []UnderutilizedRDSInstance
	OrphanedSnapshots         []OrphanedSnapshot
	UnusedElasticIPs          []UnusedElasticIP
	TotalPotentialSavings     float64
}

func NewAuditor(ctx context.Context, region string) (*Auditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &Auditor{
		ec2Client:        ec2.NewFromConfig(cfg),
		cloudwatchClient: cloudwatch.NewFromConfig(cfg),
		region:           region,
	}, nil
}

func (a *Auditor) FindUnattachedVolumes(ctx context.Context) ([]UnattachedVolume, error) {
	input := &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"available"},
			},
		},
	}

	result, err := a.ec2Client.DescribeVolumes(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe volumes: %w", err)
	}

	volumes := make([]UnattachedVolume, 0, len(result.Volumes))
	for _, vol := range result.Volumes {
		cost := calculateEBSCost(aws.ToInt32(vol.Size), string(vol.VolumeType))
		
		volumes = append(volumes, UnattachedVolume{
			VolumeID:         aws.ToString(vol.VolumeId),
			Size:             aws.ToInt32(vol.Size),
			VolumeType:       string(vol.VolumeType),
			AvailabilityZone: aws.ToString(vol.AvailabilityZone),
			CreateTime:       aws.ToTime(vol.CreateTime),
			MonthlyCost:      cost,
		})
	}

	return volumes, nil
}

func (a *Auditor) FindUnusedElasticIPs(ctx context.Context) ([]UnusedElasticIP, error) {
	input := &ec2.DescribeAddressesInput{}

	result, err := a.ec2Client.DescribeAddresses(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe addresses: %w", err)
	}

	elasticIPs := make([]UnusedElasticIP, 0)
	for _, addr := range result.Addresses {
		// Check if the EIP is not associated with any instance
		if addr.AssociationId == nil || aws.ToString(addr.AssociationId) == "" {
			elasticIPs = append(elasticIPs, UnusedElasticIP{
				AllocationID: aws.ToString(addr.AllocationId),
				PublicIP:     aws.ToString(addr.PublicIp),
				MonthlyCost:  3.60, // $3.60/month per unused EIP
			})
		}
	}

	return elasticIPs, nil
}

func (a *Auditor) FindUnderutilizedInstances(ctx context.Context) ([]UnderutilizedInstance, error) {
	// Get all running instances
	input := &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	}

	result, err := a.ec2Client.DescribeInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	instances := make([]UnderutilizedInstance, 0)
	
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Get CPU metrics from CloudWatch
			avgCPU, err := a.getInstanceCPUUtilization(ctx, aws.ToString(instance.InstanceId))
			if err != nil {
				// Log error but continue
				fmt.Printf("Warning: failed to get CPU metrics for %s: %v\n", aws.ToString(instance.InstanceId), err)
				avgCPU = -1.0 // Unknown
			}

			// Flag instances with < 5% CPU utilization
			if avgCPU >= 0 && avgCPU < 5.0 {
				cost := estimateEC2Cost(string(instance.InstanceType))
				
				instances = append(instances, UnderutilizedInstance{
					InstanceID:        aws.ToString(instance.InstanceId),
					InstanceType:      string(instance.InstanceType),
					State:             string(instance.State.Name),
					AvgCPUUtilization: avgCPU,
					MonthlyCost:       cost,
					LaunchTime:        aws.ToTime(instance.LaunchTime),
				})
			}
		}
	}

	return instances, nil
}

func (a *Auditor) FindOrphanedSnapshots(ctx context.Context) ([]OrphanedSnapshot, error) {
	// Get all snapshots owned by this account
	input := &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	}

	result, err := a.ec2Client.DescribeSnapshots(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe snapshots: %w", err)
	}

	// Get all volume IDs to check if snapshot source still exists
	volumesInput := &ec2.DescribeVolumesInput{}
	volumesResult, err := a.ec2Client.DescribeVolumes(ctx, volumesInput)
	if err != nil {
		return nil, fmt.Errorf("failed to describe volumes: %w", err)
	}

	volumeIDs := make(map[string]bool)
	for _, vol := range volumesResult.Volumes {
		volumeIDs[aws.ToString(vol.VolumeId)] = true
	}

	snapshots := make([]OrphanedSnapshot, 0)
	for _, snap := range result.Snapshots {
		// Check if the source volume no longer exists
		if !volumeIDs[aws.ToString(snap.VolumeId)] {
			cost := calculateSnapshotCost(aws.ToInt32(snap.VolumeSize))
			
			snapshots = append(snapshots, OrphanedSnapshot{
				SnapshotID:  aws.ToString(snap.SnapshotId),
				Size:        aws.ToInt32(snap.VolumeSize),
				CreateTime:  aws.ToTime(snap.StartTime),
				Description: aws.ToString(snap.Description),
				MonthlyCost: cost,
			})
		}
	}

	return snapshots, nil
}

func (a *Auditor) getInstanceCPUUtilization(ctx context.Context, instanceID string) (float64, error) {
	endTime := time.Now()
	startTime := endTime.Add(-7 * 24 * time.Hour) // Last 7 days

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/EC2"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cloudwatchtypes.Dimension{
			{
				Name:  aws.String("InstanceId"),
				Value: aws.String(instanceID),
			},
		},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(3600), // 1 hour periods
		Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticAverage},
	}

	result, err := a.cloudwatchClient.GetMetricStatistics(ctx, input)
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, fmt.Errorf("no datapoints found")
	}

	// Calculate average
	var sum float64
	for _, dp := range result.Datapoints {
		sum += aws.ToFloat64(dp.Average)
	}

	return sum / float64(len(result.Datapoints)), nil
}

func (r *AuditResults) CalculateSavings() {
	total := 0.0

	for _, vol := range r.UnattachedVolumes {
		total += vol.MonthlyCost
	}

	for _, inst := range r.UnderutilizedInstances {
		total += inst.MonthlyCost
	}

	for _, rds := range r.UnderutilizedRDSInstances {
		total += rds.MonthlyCost
	}

	for _, snap := range r.OrphanedSnapshots {
		total += snap.MonthlyCost
	}

	for _, eip := range r.UnusedElasticIPs {
		total += eip.MonthlyCost
	}

	r.TotalPotentialSavings = total
}

// Cost estimation functions (simplified - actual costs vary by region and usage)
func calculateEBSCost(sizeGB int32, volumeType string) float64 {
	pricePerGB := 0.10 // Default gp3 price per GB-month
	
	switch volumeType {
	case "gp2":
		pricePerGB = 0.10
	case "gp3":
		pricePerGB = 0.08
	case "io1", "io2":
		pricePerGB = 0.125
	case "st1":
		pricePerGB = 0.045
	case "sc1":
		pricePerGB = 0.015
	}

	return float64(sizeGB) * pricePerGB
}

func calculateSnapshotCost(sizeGB int32) float64 {
	return float64(sizeGB) * 0.05 // $0.05 per GB-month
}

func estimateEC2Cost(instanceType string) float64 {
	// Simplified cost estimation (actual costs vary by region)
	costs := map[string]float64{
		"t2.micro":  10.00,
		"t2.small":  20.00,
		"t2.medium": 40.00,
		"t3.micro":  9.00,
		"t3.small":  18.00,
		"t3.medium": 36.00,
		"m5.large":  88.00,
		"m5.xlarge": 176.00,
	}

	if cost, ok := costs[instanceType]; ok {
		return cost
	}

	return 100.00 // Default estimate
}
