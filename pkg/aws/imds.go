package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// imdsv1RiskNote explains, in plain language, why IMDSv1 being reachable is a
// security problem worth flagging.
const imdsv1RiskNote = "IMDSv1 enabled: SSRF attacks can steal IAM credentials via metadata service (cf. Capital One breach 2019)"

// IMDSAuditor inspects EC2 instances for the Instance Metadata Service version
// they enforce.
type IMDSAuditor struct {
	ec2Client *ec2.Client
	region    string
}

// IMDSFinding describes a running instance that still accepts IMDSv1 requests.
type IMDSFinding struct {
	InstanceID   string
	InstanceType string
	InstanceName string // from the Name tag; empty if untagged
	HttpTokens   string // "optional" or "" (nil in the API) means IMDSv1 allowed
	RiskNote     string
	Remediation  string
}

// NewIMDSAuditor creates a new IMDSAuditor for the given region.
func NewIMDSAuditor(ctx context.Context, region string) (*IMDSAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &IMDSAuditor{
		ec2Client: ec2.NewFromConfig(cfg),
		region:    region,
	}, nil
}

// FindInstancesWithIMDSv1 returns running instances whose metadata options do
// not require IMDSv2 (HttpTokens != "required"), meaning IMDSv1 is still
// reachable.
func (a *IMDSAuditor) FindInstancesWithIMDSv1(ctx context.Context) ([]IMDSFinding, error) {
	input := &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	}

	findings := make([]IMDSFinding, 0)
	var nextToken *string

	for {
		input.NextToken = nextToken
		result, err := a.ec2Client.DescribeInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range result.Reservations {
			for _, instance := range reservation.Instances {
				httpTokens := ""
				if instance.MetadataOptions != nil {
					httpTokens = string(instance.MetadataOptions.HttpTokens)
				}

				// "required" enforces IMDSv2; anything else leaves IMDSv1 reachable.
				if !imdsv1Allowed(httpTokens) {
					continue
				}

				instanceID := aws.ToString(instance.InstanceId)
				findings = append(findings, IMDSFinding{
					InstanceID:   instanceID,
					InstanceType: string(instance.InstanceType),
					InstanceName: instanceNameTag(instance.Tags),
					HttpTokens:   httpTokens,
					RiskNote:     imdsv1RiskNote,
					Remediation:  imdsRemediation(instanceID, a.region),
				})
			}
		}

		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	return findings, nil
}

// imdsv1Allowed reports whether the given HttpTokens value still permits IMDSv1.
// Only the explicit "required" setting enforces IMDSv2; "optional" or an unset
// value (nil in the API) leaves IMDSv1 reachable.
func imdsv1Allowed(httpTokens string) bool {
	return httpTokens != "required"
}

// imdsRemediation returns the AWS CLI command that enforces IMDSv2 on an
// instance.
func imdsRemediation(instanceID, region string) string {
	return fmt.Sprintf("aws ec2 modify-instance-metadata-options --instance-id %s --http-tokens required --region %s", instanceID, region)
}

// instanceNameTag returns the value of the "Name" tag, or "" when it is absent.
func instanceNameTag(tags []ec2types.Tag) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "Name" {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}
