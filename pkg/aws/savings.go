package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

type SavingsAnalyzer struct {
	client *costexplorer.Client
	region string
}

type ReservationRecommendation struct {
	InstanceType                 string
	InstanceCount                int32
	EstimatedMonthlySavings      float64
	EstimatedMonthlyOnDemandCost float64
	UpfrontCost                  float64
}

type SavingsPlanRecommendation struct {
	HourlyCommitment           string
	EstimatedMonthlySavings    float64
	EstimatedSavingsPercentage float64
}

func NewSavingsAnalyzer(ctx context.Context, region string) (*SavingsAnalyzer, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &SavingsAnalyzer{
		client: costexplorer.NewFromConfig(cfg),
		region: region,
	}, nil
}

func (s *SavingsAnalyzer) GetReservationRecommendations(ctx context.Context) ([]ReservationRecommendation, error) {
	recommendations := make([]ReservationRecommendation, 0)

	input := &costexplorer.GetReservationPurchaseRecommendationInput{
		Service:              aws.String("Amazon Elastic Compute Cloud - Compute"),
		LookbackPeriodInDays: cetypes.LookbackPeriodInDaysThirtyDays,
		TermInYears:          cetypes.TermInYearsOneYear,
		PaymentOption:        cetypes.PaymentOptionNoUpfront,
	}

	result, err := s.client.GetReservationPurchaseRecommendation(ctx, input)
	if err != nil {
		// Insufficient lookback history surfaces as DataUnavailableException;
		// treat only that as "nothing to recommend". Any other error (e.g.
		// permissions, throttling) is a real problem and must propagate.
		var unavailable *cetypes.DataUnavailableException
		if errors.As(err, &unavailable) {
			return recommendations, nil
		}
		return nil, fmt.Errorf("failed to get reservation purchase recommendation: %w", err)
	}

	for _, rec := range result.Recommendations {
		for _, detail := range rec.RecommendationDetails {
			instanceType := ""
			if detail.InstanceDetails != nil && detail.InstanceDetails.EC2InstanceDetails != nil {
				instanceType = aws.ToString(detail.InstanceDetails.EC2InstanceDetails.InstanceType)
			}

			recommendations = append(recommendations, ReservationRecommendation{
				InstanceType:                 instanceType,
				InstanceCount:                int32(parseFloat(aws.ToString(detail.RecommendedNumberOfInstancesToPurchase))),
				EstimatedMonthlySavings:      parseFloat(aws.ToString(detail.EstimatedMonthlySavingsAmount)),
				EstimatedMonthlyOnDemandCost: parseFloat(aws.ToString(detail.EstimatedMonthlyOnDemandCost)),
				UpfrontCost:                  parseFloat(aws.ToString(detail.UpfrontCost)),
			})
		}
	}

	return recommendations, nil
}

func (s *SavingsAnalyzer) GetSavingsPlanRecommendations(ctx context.Context) ([]SavingsPlanRecommendation, error) {
	recommendations := make([]SavingsPlanRecommendation, 0)

	input := &costexplorer.GetSavingsPlansPurchaseRecommendationInput{
		SavingsPlansType:     cetypes.SupportedSavingsPlansTypeComputeSp,
		TermInYears:          cetypes.TermInYearsOneYear,
		PaymentOption:        cetypes.PaymentOptionNoUpfront,
		LookbackPeriodInDays: cetypes.LookbackPeriodInDaysThirtyDays,
	}

	result, err := s.client.GetSavingsPlansPurchaseRecommendation(ctx, input)
	if err != nil {
		// Same as reservations: only swallow the insufficient-history case.
		var unavailable *cetypes.DataUnavailableException
		if errors.As(err, &unavailable) {
			return recommendations, nil
		}
		return nil, fmt.Errorf("failed to get savings plans purchase recommendation: %w", err)
	}

	if result.SavingsPlansPurchaseRecommendation == nil {
		return recommendations, nil
	}

	for _, detail := range result.SavingsPlansPurchaseRecommendation.SavingsPlansPurchaseRecommendationDetails {
		recommendations = append(recommendations, SavingsPlanRecommendation{
			HourlyCommitment:           aws.ToString(detail.HourlyCommitmentToPurchase),
			EstimatedMonthlySavings:    parseFloat(aws.ToString(detail.EstimatedMonthlySavingsAmount)),
			EstimatedSavingsPercentage: parseFloat(aws.ToString(detail.EstimatedSavingsPercentage)),
		})
	}

	return recommendations, nil
}
