package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// lambdaGBSecondRate is the approximate AWS Lambda price per GB-second of
// compute (simplified us-east-1 pricing; actual costs vary by region and free
// tier).
const lambdaGBSecondRate = 0.0000166667

// Overprovisioning thresholds: a function is flagged only when it reserves a
// lot of memory but runs briefly and infrequently.
const (
	overprovisionedMinMemoryMB           = 512
	overprovisionedMaxDurationMs         = 200.0
	overprovisionedMaxDailyInvokes       = 1000.0
	lambdaMinMemoryMB              int32 = 128
)

// deprecatedLambdaRuntimes lists runtimes AWS no longer patches. go1.x is
// handled separately as an EOL-announced warning rather than a hard deprecation.
var deprecatedLambdaRuntimes = map[string]bool{
	"nodejs10.x":    true,
	"nodejs12.x":    true,
	"nodejs14.x":    true,
	"python2.7":     true,
	"python3.6":     true,
	"python3.7":     true,
	"python3.8":     true,
	"java8":         true,
	"dotnetcore2.1": true,
	"dotnetcore3.1": true,
	"ruby2.5":       true,
}

// LambdaAuditor inspects Lambda functions for deprecated runtimes, unauthenticated
// function URLs, and over-provisioned memory.
type LambdaAuditor struct {
	lambdaClient     *lambda.Client
	cloudwatchClient *cloudwatch.Client
	region           string
}

// LambdaFinding describes a single Lambda security or cost issue.
type LambdaFinding struct {
	FunctionName        string
	Runtime             string
	Issue               string // "deprecated_runtime", "public_url", "overprovisioned"
	MemoryMB            int32
	RecommendedMemoryMB int32 // 0 when not applicable
	MonthlyCost         float64
	RiskNote            string
}

// NewLambdaAuditor creates a new LambdaAuditor for the given region.
func NewLambdaAuditor(ctx context.Context, region string) (*LambdaAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &LambdaAuditor{
		lambdaClient:     lambda.NewFromConfig(cfg),
		cloudwatchClient: cloudwatch.NewFromConfig(cfg),
		region:           region,
	}, nil
}

// FindDeprecatedRuntimes flags functions running deprecated (or EOL-announced)
// runtimes.
func (a *LambdaAuditor) FindDeprecatedRuntimes(ctx context.Context) ([]LambdaFinding, error) {
	functions, err := a.listFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]LambdaFinding, 0, len(functions))
	for _, fn := range functions {
		runtime := string(fn.Runtime)
		flagged, note := classifyRuntime(runtime)
		if !flagged {
			continue
		}

		findings = append(findings, LambdaFinding{
			FunctionName: aws.ToString(fn.FunctionName),
			Runtime:      runtime,
			Issue:        "deprecated_runtime",
			MemoryMB:     aws.ToInt32(fn.MemorySize),
			RiskNote:     note,
		})
	}

	return findings, nil
}

// FindPublicFunctionURLs flags functions whose Function URL is configured with
// AuthType NONE (no IAM authentication).
func (a *LambdaAuditor) FindPublicFunctionURLs(ctx context.Context) ([]LambdaFinding, error) {
	functions, err := a.listFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]LambdaFinding, 0)
	for _, fn := range functions {
		name := aws.ToString(fn.FunctionName)

		out, err := a.lambdaClient.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{
			FunctionName: fn.FunctionName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list function URL configs for %s: %w", name, err)
		}

		for _, urlConfig := range out.FunctionUrlConfigs {
			if urlConfig.AuthType == lambdatypes.FunctionUrlAuthTypeNone {
				findings = append(findings, LambdaFinding{
					FunctionName: name,
					Runtime:      string(fn.Runtime),
					Issue:        "public_url",
					MemoryMB:     aws.ToInt32(fn.MemorySize),
					RiskNote:     "Function URL uses AuthType NONE: the function is invocable by anyone on the internet without authentication",
				})
			}
		}
	}

	return findings, nil
}

// FindOverprovisionedFunctions flags functions that reserve a lot of memory but
// run briefly and infrequently, estimating the monthly cost and a downsizing
// target.
func (a *LambdaAuditor) FindOverprovisionedFunctions(ctx context.Context) ([]LambdaFinding, error) {
	functions, err := a.listFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]LambdaFinding, 0)
	for _, fn := range functions {
		name := aws.ToString(fn.FunctionName)
		memoryMB := aws.ToInt32(fn.MemorySize)

		avgDurationMs, err := a.avgDurationMs(ctx, name)
		if err != nil {
			fmt.Printf("Warning: failed to get duration metrics for %s: %v\n", name, err)
			continue
		}
		totalInvocations, err := a.totalInvocations(ctx, name)
		if err != nil {
			fmt.Printf("Warning: failed to get invocation metrics for %s: %v\n", name, err)
			continue
		}

		dailyInvocations := totalInvocations / lambdaMetricLookbackDays
		if !isOverprovisioned(memoryMB, avgDurationMs, dailyInvocations) {
			continue
		}

		monthlyInvocations := dailyInvocations * 30
		memoryGB := float64(memoryMB) / 1024
		cost := lambdaMonthlyCost(monthlyInvocations, avgDurationMs/1000, memoryGB)

		findings = append(findings, LambdaFinding{
			FunctionName:        name,
			Runtime:             string(fn.Runtime),
			Issue:               "overprovisioned",
			MemoryMB:            memoryMB,
			RecommendedMemoryMB: recommendedMemory(memoryMB),
			MonthlyCost:         cost,
			RiskNote:            fmt.Sprintf("%dMB reserved but avg duration %.0fms over %.0f invocations/day; consider downsizing", memoryMB, avgDurationMs, dailyInvocations),
		})
	}

	return findings, nil
}

// lambdaMetricLookbackDays is the trailing window used for CloudWatch metrics.
const lambdaMetricLookbackDays = 7.0

// listFunctions returns every Lambda function configuration in the region,
// following pagination via NextMarker.
func (a *LambdaAuditor) listFunctions(ctx context.Context) ([]lambdatypes.FunctionConfiguration, error) {
	functions := make([]lambdatypes.FunctionConfiguration, 0)
	var marker *string

	for {
		out, err := a.lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list functions: %w", err)
		}

		functions = append(functions, out.Functions...)

		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}

	return functions, nil
}

// avgDurationMs returns the 7-day average execution duration in milliseconds.
func (a *LambdaAuditor) avgDurationMs(ctx context.Context, functionName string) (float64, error) {
	avg, ok, err := a.lambdaMetricStat(ctx, functionName, "Duration", cloudwatchtypes.StatisticAverage)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return avg, nil
}

// totalInvocations returns the total number of invocations over the 7-day window.
func (a *LambdaAuditor) totalInvocations(ctx context.Context, functionName string) (float64, error) {
	total, _, err := a.lambdaMetricStat(ctx, functionName, "Invocations", cloudwatchtypes.StatisticSum)
	if err != nil {
		return 0, err
	}
	return total, nil
}

// lambdaMetricStat reads an AWS/Lambda metric for one function over the lookback
// window. For the Average statistic it returns the mean across datapoints; for
// Sum it returns the total. The bool reports whether any datapoints existed.
func (a *LambdaAuditor) lambdaMetricStat(ctx context.Context, functionName, metricName string, stat cloudwatchtypes.Statistic) (float64, bool, error) {
	endTime := time.Now()
	startTime := endTime.Add(-lambdaMetricLookbackDays * 24 * time.Hour)

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/Lambda"),
		MetricName: aws.String(metricName),
		Dimensions: []cloudwatchtypes.Dimension{
			{Name: aws.String("FunctionName"), Value: aws.String(functionName)},
		},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(86400), // 1 day periods
		Statistics: []cloudwatchtypes.Statistic{stat},
	}

	result, err := a.cloudwatchClient.GetMetricStatistics(ctx, input)
	if err != nil {
		return 0, false, err
	}

	if len(result.Datapoints) == 0 {
		return 0, false, nil
	}

	var sum float64
	for _, dp := range result.Datapoints {
		if stat == cloudwatchtypes.StatisticSum {
			sum += aws.ToFloat64(dp.Sum)
		} else {
			sum += aws.ToFloat64(dp.Average)
		}
	}

	if stat == cloudwatchtypes.StatisticSum {
		return sum, true, nil
	}
	return sum / float64(len(result.Datapoints)), true, nil
}

// classifyRuntime reports whether a runtime should be flagged and, if so, the
// risk note. Deprecated runtimes are hard findings; go1.x is an EOL-announced
// warning.
func classifyRuntime(runtime string) (bool, string) {
	if deprecatedLambdaRuntimes[runtime] {
		return true, fmt.Sprintf("runtime %s is deprecated; AWS no longer provides security patches or guaranteed availability", runtime)
	}
	if runtime == "go1.x" {
		return true, "runtime go1.x is EOL-announced; migrate to the provided.al2 (custom) runtime before support ends"
	}
	return false, ""
}

// lambdaMonthlyCost computes the estimated monthly compute cost from the
// monthly invocation count, per-invocation duration in seconds, and reserved
// memory in GB.
func lambdaMonthlyCost(monthlyInvocations, durationSeconds, memoryGB float64) float64 {
	return monthlyInvocations * durationSeconds * memoryGB * lambdaGBSecondRate
}

// isOverprovisioned reports whether a function reserves a lot of memory yet runs
// briefly and infrequently.
func isOverprovisioned(memoryMB int32, avgDurationMs, dailyInvocations float64) bool {
	return memoryMB >= overprovisionedMinMemoryMB &&
		avgDurationMs < overprovisionedMaxDurationMs &&
		dailyInvocations < overprovisionedMaxDailyInvokes
}

// recommendedMemory suggests halving the reserved memory, never dropping below
// the Lambda floor of 128MB.
func recommendedMemory(memoryMB int32) int32 {
	rec := memoryMB / 2
	if rec < lambdaMinMemoryMB {
		return lambdaMinMemoryMB
	}
	return rec
}
