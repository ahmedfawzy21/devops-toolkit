package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Flat-rate provisioned capacity pricing (simplified - actual costs vary by region).
const (
	rcuHourlyRate = 0.00065 // $ per provisioned RCU-hour
	wcuHourlyRate = 0.00065 // $ per provisioned WCU-hour
)

type DynamoDBAuditor struct {
	dynamodbClient   *dynamodb.Client
	cloudwatchClient *cloudwatch.Client
	region           string
}

type DynamoDBFinding struct {
	TableName      string
	Issue          string // e.g. "no_pitr" or "overprovisioned"
	ProvisionedRCU int64
	ProvisionedWCU int64
	ConsumedRCU    float64
	ConsumedWCU    float64
	MonthlyCost    float64
}

func NewDynamoDBAuditor(ctx context.Context, region string) (*DynamoDBAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &DynamoDBAuditor{
		dynamodbClient:   dynamodb.NewFromConfig(cfg),
		cloudwatchClient: cloudwatch.NewFromConfig(cfg),
		region:           region,
	}, nil
}

func (d *DynamoDBAuditor) FindTablesWithoutPITR(ctx context.Context) ([]DynamoDBFinding, error) {
	tableNames, err := d.listTables(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]DynamoDBFinding, 0, len(tableNames))
	for _, name := range tableNames {
		result, err := d.dynamodbClient.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
			TableName: aws.String(name),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe continuous backups for %s: %w", name, err)
		}

		status := dynamodbtypes.PointInTimeRecoveryStatusDisabled
		if desc := result.ContinuousBackupsDescription; desc != nil && desc.PointInTimeRecoveryDescription != nil {
			status = desc.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
		}

		if status != dynamodbtypes.PointInTimeRecoveryStatusEnabled {
			findings = append(findings, DynamoDBFinding{
				TableName: name,
				Issue:     "no_pitr",
			})
		}
	}

	return findings, nil
}

func (d *DynamoDBAuditor) FindOverprovisionedTables(ctx context.Context) ([]DynamoDBFinding, error) {
	tableNames, err := d.listTables(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]DynamoDBFinding, 0, len(tableNames))
	for _, name := range tableNames {
		result, err := d.dynamodbClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(name),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe table %s: %w", name, err)
		}

		table := result.Table
		if table == nil || !isProvisionedTable(table) {
			continue
		}

		provRCU := aws.ToInt64(table.ProvisionedThroughput.ReadCapacityUnits)
		provWCU := aws.ToInt64(table.ProvisionedThroughput.WriteCapacityUnits)
		if provRCU == 0 && provWCU == 0 {
			continue
		}

		consumedRCU, err := d.getConsumedCapacity(ctx, name, "ConsumedReadCapacityUnits")
		if err != nil {
			fmt.Printf("Warning: failed to get read capacity metrics for %s: %v\n", name, err)
			continue
		}
		consumedWCU, err := d.getConsumedCapacity(ctx, name, "ConsumedWriteCapacityUnits")
		if err != nil {
			fmt.Printf("Warning: failed to get write capacity metrics for %s: %v\n", name, err)
			continue
		}

		// Flag if either read or write utilization is below 20%
		if isUnderutilized(provRCU, consumedRCU) || isUnderutilized(provWCU, consumedWCU) {
			cost := calculateDynamoDBWaste(provRCU, provWCU, consumedRCU, consumedWCU)

			findings = append(findings, DynamoDBFinding{
				TableName:      name,
				Issue:          "overprovisioned",
				ProvisionedRCU: provRCU,
				ProvisionedWCU: provWCU,
				ConsumedRCU:    consumedRCU,
				ConsumedWCU:    consumedWCU,
				MonthlyCost:    cost,
			})
		}
	}

	return findings, nil
}

func (d *DynamoDBAuditor) listTables(ctx context.Context) ([]string, error) {
	names := make([]string, 0)
	var lastEvaluated *string

	for {
		result, err := d.dynamodbClient.ListTables(ctx, &dynamodb.ListTablesInput{
			ExclusiveStartTableName: lastEvaluated,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list tables: %w", err)
		}

		names = append(names, result.TableNames...)

		if result.LastEvaluatedTableName == nil {
			break
		}
		lastEvaluated = result.LastEvaluatedTableName
	}

	return names, nil
}

// getConsumedCapacity returns the 7-day average consumed capacity units per second.
func (d *DynamoDBAuditor) getConsumedCapacity(ctx context.Context, tableName, metricName string) (float64, error) {
	endTime := time.Now()
	startTime := endTime.Add(-7 * 24 * time.Hour) // Last 7 days

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/DynamoDB"),
		MetricName: aws.String(metricName),
		Dimensions: []cloudwatchtypes.Dimension{
			{
				Name:  aws.String("TableName"),
				Value: aws.String(tableName),
			},
		},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(3600), // 1 hour periods
		Statistics: []cloudwatchtypes.Statistic{cloudwatchtypes.StatisticSum},
	}

	result, err := d.cloudwatchClient.GetMetricStatistics(ctx, input)
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, nil
	}

	// Each datapoint is the summed consumed units over the period; convert to a
	// per-second rate to compare against provisioned capacity units.
	var sum float64
	for _, dp := range result.Datapoints {
		sum += aws.ToFloat64(dp.Sum) / 3600.0
	}

	return sum / float64(len(result.Datapoints)), nil
}

func isProvisionedTable(table *dynamodbtypes.TableDescription) bool {
	// BillingModeSummary is nil for tables created with the default PROVISIONED mode.
	if table.BillingModeSummary == nil {
		return table.ProvisionedThroughput != nil
	}
	return table.BillingModeSummary.BillingMode == dynamodbtypes.BillingModeProvisioned
}

func isUnderutilized(provisioned int64, consumed float64) bool {
	if provisioned == 0 {
		return false
	}
	return consumed/float64(provisioned) < 0.20
}

// calculateDynamoDBWaste estimates the monthly cost of unused provisioned
// capacity (simplified flat-rate estimate).
func calculateDynamoDBWaste(provRCU, provWCU int64, consumedRCU, consumedWCU float64) float64 {
	const hoursPerMonth = 730.0

	wastedRCU := float64(provRCU) - consumedRCU
	if wastedRCU < 0 {
		wastedRCU = 0
	}
	wastedWCU := float64(provWCU) - consumedWCU
	if wastedWCU < 0 {
		wastedWCU = 0
	}

	return wastedRCU*rcuHourlyRate*hoursPerMonth + wastedWCU*wcuHourlyRate*hoursPerMonth
}
