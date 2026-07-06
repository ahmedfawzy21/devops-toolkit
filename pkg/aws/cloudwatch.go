package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type CloudWatchAuditor struct {
	logsClient       *cloudwatchlogs.Client
	cloudwatchClient *cloudwatch.Client
	region           string
}

type LogGroupFinding struct {
	Name              string
	RetentionDays     int32 // -1 means no retention policy set
	StoredBytes       int64
	LastIngestionDays int
	MonthlyCost       float64
	Reason            string
}

func NewCloudWatchAuditor(ctx context.Context, region string) (*CloudWatchAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &CloudWatchAuditor{
		logsClient:       cloudwatchlogs.NewFromConfig(cfg),
		cloudwatchClient: cloudwatch.NewFromConfig(cfg),
		region:           region,
	}, nil
}

func (c *CloudWatchAuditor) FindLogGroupsWithoutRetention(ctx context.Context) ([]LogGroupFinding, error) {
	groups, err := c.listLogGroups(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]LogGroupFinding, 0, len(groups))
	for _, group := range groups {
		// Flag groups that never expire (no retention policy set)
		if group.RetentionInDays != nil {
			continue
		}

		storedBytes := aws.ToInt64(group.StoredBytes)
		cost := calculateLogStorageCost(storedBytes)

		findings = append(findings, LogGroupFinding{
			Name:              aws.ToString(group.LogGroupName),
			RetentionDays:     -1,
			StoredBytes:       storedBytes,
			LastIngestionDays: -1,
			MonthlyCost:       cost,
			Reason:            "no retention policy set; logs are stored indefinitely",
		})
	}

	return findings, nil
}

func (c *CloudWatchAuditor) FindDeadLogGroups(ctx context.Context) ([]LogGroupFinding, error) {
	groups, err := c.listLogGroups(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]LogGroupFinding, 0, len(groups))
	for _, group := range groups {
		name := aws.ToString(group.LogGroupName)

		events, lastIngestionDays, err := c.getIncomingLogEvents(ctx, name)
		if err != nil {
			// Log error but continue, consistent with the EC2/RDS auditors
			fmt.Printf("Warning: failed to get log metrics for %s: %v\n", name, err)
			continue
		}

		// Flag groups with zero incoming events over the last 30 days
		if events == 0 {
			storedBytes := aws.ToInt64(group.StoredBytes)
			cost := calculateLogStorageCost(storedBytes)

			retentionDays := int32(-1)
			if group.RetentionInDays != nil {
				retentionDays = aws.ToInt32(group.RetentionInDays)
			}

			findings = append(findings, LogGroupFinding{
				Name:              name,
				RetentionDays:     retentionDays,
				StoredBytes:       storedBytes,
				LastIngestionDays: lastIngestionDays,
				MonthlyCost:       cost,
				Reason:            "no incoming log events in the last 30 days",
			})
		}
	}

	return findings, nil
}

func (c *CloudWatchAuditor) listLogGroups(ctx context.Context) ([]cloudwatchlogstypes.LogGroup, error) {
	groups := make([]cloudwatchlogstypes.LogGroup, 0)
	var nextToken *string

	for {
		result, err := c.logsClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe log groups: %w", err)
		}

		groups = append(groups, result.LogGroups...)

		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	return groups, nil
}

// getIncomingLogEvents returns the total incoming log events over the last 30
// days and the number of days since the most recent ingestion (30 if none).
func (c *CloudWatchAuditor) getIncomingLogEvents(ctx context.Context, logGroupName string) (float64, int, error) {
	endTime := time.Now()
	startTime := endTime.Add(-30 * 24 * time.Hour) // Last 30 days

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/Logs"),
		MetricName: aws.String("IncomingLogEvents"),
		Dimensions: []cloudwatchtypes.Dimension{
			{
				Name:  aws.String("LogGroupName"),
				Value: aws.String(logGroupName),
			},
		},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(86400), // 1 day periods
		Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticSum},
	}

	result, err := c.cloudwatchClient.GetMetricStatistics(ctx, input)
	if err != nil {
		return 0, 0, err
	}

	var total float64
	var lastIngestion time.Time
	for _, dp := range result.Datapoints {
		sum := aws.ToFloat64(dp.Sum)
		total += sum
		if sum > 0 {
			ts := aws.ToTime(dp.Timestamp)
			if ts.After(lastIngestion) {
				lastIngestion = ts
			}
		}
	}

	lastIngestionDays := 30
	if !lastIngestion.IsZero() {
		lastIngestionDays = int(endTime.Sub(lastIngestion).Hours() / 24)
	}

	return total, lastIngestionDays, nil
}

// calculateLogStorageCost estimates monthly CloudWatch Logs storage cost
// (simplified - $0.03 per GB-month for standard storage).
func calculateLogStorageCost(storedBytes int64) float64 {
	const pricePerGBMonth = 0.03
	gb := float64(storedBytes) / (1024 * 1024 * 1024)
	return gb * pricePerGBMonth
}
