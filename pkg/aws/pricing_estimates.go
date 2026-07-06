package aws

// EC2OnDemandHourly holds simplified On-Demand hourly rates in USD
// (approximate us-east-1 Linux pricing; actual costs vary by region and OS).
var EC2OnDemandHourly = map[string]float64{
	"t3.micro":   0.0104,
	"t3.small":   0.0208,
	"t3.medium":  0.0416,
	"t3.large":   0.0832,
	"m5.large":   0.096,
	"m5.xlarge":  0.192,
	"m5.2xlarge": 0.384,
	"c5.large":   0.085,
	"c5.xlarge":  0.17,
	"r5.large":   0.126,
	"r5.xlarge":  0.252,
}

// riNoUpfrontDiscount is the approximate discount of a 1-year No-Upfront
// Reserved Instance versus On-Demand. This is a rough simplification; real RI
// pricing varies by region, AZ, platform, and instance family.
const riNoUpfrontDiscount = 0.35

// EstimateRICost returns the approximate effective hourly rate for a 1-year
// No-Upfront Reserved Instance. Only "1yr" / "ONE_YEAR" terms are modeled; any
// other term falls back to the On-Demand rate. Returns 0 for unknown types.
func EstimateRICost(instanceType string, term string) float64 {
	onDemand, ok := EC2OnDemandHourly[instanceType]
	if !ok {
		return 0
	}

	switch term {
	case "1yr", "ONE_YEAR", "one_year":
		return onDemand * (1 - riNoUpfrontDiscount)
	default:
		return onDemand
	}
}

// MonthlyFromHourly converts an hourly rate to a monthly cost using the
// AWS convention of 730 hours per month.
func MonthlyFromHourly(hourlyRate float64) float64 {
	return hourlyRate * 730
}
