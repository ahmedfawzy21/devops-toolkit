package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

type CostAnalyzer struct {
	client *costexplorer.Client
	region string
}

type CostItem struct {
	Name   string
	Amount float64
	Unit   string
}

type CostResults struct {
	StartDate    time.Time
	EndDate      time.Time
	TotalCost    float64
	Currency     string
	GroupBy      string
	Items        []CostItem
	DailyTrend   []DailyCost
}

type DailyCost struct {
	Date   string
	Amount float64
}

func NewCostAnalyzer(ctx context.Context, region string) (*CostAnalyzer, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &CostAnalyzer{
		client: costexplorer.NewFromConfig(cfg),
		region: region,
	}, nil
}

func (c *CostAnalyzer) GetCostAndUsage(ctx context.Context, startDate, endDate time.Time, groupBy string) (*CostResults, error) {
	// Format dates for Cost Explorer API
	start := startDate.Format("2006-01-02")
	end := endDate.Format("2006-01-02")

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: aws.String(start),
			End:   aws.String(end),
		},
		Granularity: cetypes.GranularityDaily,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  aws.String(groupBy),
			},
		},
	}

	result, err := c.client.GetCostAndUsage(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get cost and usage: %w", err)
	}

	// Process results
	costMap := make(map[string]float64)
	dailyCosts := make([]DailyCost, 0)
	totalCost := 0.0
	currency := "USD"

	for _, resultByTime := range result.ResultsByTime {
		dailyTotal := 0.0
		
		for _, group := range resultByTime.Groups {
			if len(group.Keys) > 0 && len(group.Metrics) > 0 {
				key := group.Keys[0]
				
				if amountStr, ok := group.Metrics["UnblendedCost"]; ok {
					amount := parseFloat(aws.ToString(amountStr.Amount))
					costMap[key] += amount
					totalCost += amount
					dailyTotal += amount
					
					if amountStr.Unit != nil {
						currency = aws.ToString(amountStr.Unit)
					}
				}
			}
		}

		dailyCosts = append(dailyCosts, DailyCost{
			Date:   aws.ToString(resultByTime.TimePeriod.Start),
			Amount: dailyTotal,
		})
	}

	// Convert map to sorted slice
	items := make([]CostItem, 0, len(costMap))
	for name, amount := range costMap {
		items = append(items, CostItem{
			Name:   name,
			Amount: amount,
			Unit:   currency,
		})
	}

	// Sort by amount descending
	sort.Slice(items, func(i, j int) bool {
		return items[i].Amount > items[j].Amount
	})

	return &CostResults{
		StartDate:  startDate,
		EndDate:    endDate,
		TotalCost:  totalCost,
		Currency:   currency,
		GroupBy:    groupBy,
		Items:      items,
		DailyTrend: dailyCosts,
	}, nil
}

func (r *CostResults) LimitToTopN(n int) {
	if len(r.Items) > n {
		// Keep top N and sum the rest as "Other"
		topN := r.Items[:n]
		other := 0.0
		for i := n; i < len(r.Items); i++ {
			other += r.Items[i].Amount
		}
		
		if other > 0 {
			topN = append(topN, CostItem{
				Name:   "Other",
				Amount: other,
				Unit:   r.Currency,
			})
		}
		
		r.Items = topN
	}
}

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}
