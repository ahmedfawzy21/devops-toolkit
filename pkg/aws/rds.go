package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

type UnderutilizedRDSInstance struct {
	InstanceID          string
	InstanceClass       string
	Engine              string
	AvgCPUUtilization   float64
	MonthlyCost         float64
}

func (a *Auditor) FindUnderutilizedRDS(ctx context.Context) ([]UnderutilizedRDSInstance, error) {
	// Create RDS client
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// Get all RDS instances
	input := &rds.DescribeDBInstancesInput{}

	result, err := rdsClient.DescribeDBInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
	}

	instances := make([]UnderutilizedRDSInstance, 0)

	for _, dbInstance := range result.DBInstances {
		// Get CPU metrics from CloudWatch
		avgCPU, err := a.getRDSCPUUtilization(ctx, aws.ToString(dbInstance.DBInstanceIdentifier))
		if err != nil {
			// Log error but continue
			fmt.Printf("Warning: failed to get CPU metrics for %s: %v\n", aws.ToString(dbInstance.DBInstanceIdentifier), err)
			avgCPU = -1.0 // Unknown
		}

		// Flag instances with < 10% average CPU utilization
		if avgCPU >= 0 && avgCPU < 10.0 {
			cost := estimateRDSCost(aws.ToString(dbInstance.DBInstanceClass))

			instances = append(instances, UnderutilizedRDSInstance{
				InstanceID:        aws.ToString(dbInstance.DBInstanceIdentifier),
				InstanceClass:     aws.ToString(dbInstance.DBInstanceClass),
				Engine:            aws.ToString(dbInstance.Engine),
				AvgCPUUtilization: avgCPU,
				MonthlyCost:       cost,
			})
		}
	}

	return instances, nil
}

func (a *Auditor) getRDSCPUUtilization(ctx context.Context, dbInstanceID string) (float64, error) {
	endTime := time.Now()
	startTime := endTime.Add(-7 * 24 * time.Hour) // Last 7 days

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cloudwatchtypes.Dimension{
			{
				Name:  aws.String("DBInstanceIdentifier"),
				Value: aws.String(dbInstanceID),
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

func estimateRDSCost(instanceClass string) float64 {
	// Simplified cost estimation (actual costs vary by region and engine)
	costs := map[string]float64{
		"db.t3.micro":  15.00,
		"db.t3.small":  30.00,
		"db.m5.large":  145.00,
	}

	if cost, ok := costs[instanceClass]; ok {
		return cost
	}

	return 100.00 // Default estimate
}
