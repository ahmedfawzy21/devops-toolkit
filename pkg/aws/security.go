package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Severity levels for security findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
)

// SecurityFinding represents a security issue found during audit
type SecurityFinding struct {
	ResourceType string
	ResourceID   string
	Region       string
	Severity     Severity
	Description  string
}

// OpenSecurityGroup represents a security group with risky open ports
type OpenSecurityGroup struct {
	GroupID   string
	GroupName string
	Port      int32
	Protocol  string
	Source    string
	Severity  Severity
}

// PublicS3Bucket represents an S3 bucket with public access
type PublicS3Bucket struct {
	BucketName   string
	PublicAccess string
	Severity     Severity
}

// SecurityResults holds all security audit findings
type SecurityResults struct {
	PublicS3Buckets    []PublicS3Bucket
	OpenSecurityGroups []OpenSecurityGroup
	Findings           []SecurityFinding
}

// SecurityAuditor handles AWS security auditing
type SecurityAuditor struct {
	ec2Client *ec2.Client
	s3Client  *s3.Client
	region    string
}

// RiskyPorts defines ports that are considered risky when exposed to the internet
var RiskyPorts = map[int32]string{
	22:    "SSH",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
}

// NewSecurityAuditor creates a new SecurityAuditor for the given region
func NewSecurityAuditor(ctx context.Context, region string) (*SecurityAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &SecurityAuditor{
		ec2Client: ec2.NewFromConfig(cfg),
		s3Client:  s3.NewFromConfig(cfg),
		region:    region,
	}, nil
}

// CheckPublicS3Buckets finds S3 buckets with public access enabled
func (s *SecurityAuditor) CheckPublicS3Buckets(ctx context.Context) ([]PublicS3Bucket, error) {
	// List all buckets
	listResult, err := s.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	publicBuckets := make([]PublicS3Bucket, 0)

	for _, bucket := range listResult.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// Check bucket location to ensure we only check buckets in our region
		// Skip region check for us-east-1 (returns empty location)
		locationResult, err := s.s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// Skip buckets we can't access
			continue
		}

		bucketRegion := string(locationResult.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}
		if bucketRegion != s.region {
			continue
		}

		// Check public access block configuration
		publicAccessBlock, err := s.s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})

		isPublic := false
		publicReason := ""

		if err != nil {
			// If GetPublicAccessBlock returns error, the bucket might not have block configured
			// Check bucket ACL instead
			aclResult, aclErr := s.s3Client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
				Bucket: bucket.Name,
			})
			if aclErr == nil {
				for _, grant := range aclResult.Grants {
					if grant.Grantee != nil && grant.Grantee.URI != nil {
						uri := aws.ToString(grant.Grantee.URI)
						if uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
							uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
							isPublic = true
							publicReason = "Public ACL"
							break
						}
					}
				}
			}
		} else {
			// Check if any public access is allowed
			config := publicAccessBlock.PublicAccessBlockConfiguration
			if config != nil {
				if !aws.ToBool(config.BlockPublicAcls) ||
					!aws.ToBool(config.BlockPublicPolicy) ||
					!aws.ToBool(config.IgnorePublicAcls) ||
					!aws.ToBool(config.RestrictPublicBuckets) {
					isPublic = true
					publicReason = "Public Access Block Disabled"
				}
			}
		}

		if isPublic {
			publicBuckets = append(publicBuckets, PublicS3Bucket{
				BucketName:   bucketName,
				PublicAccess: publicReason,
				Severity:     SeverityCritical,
			})
		}
	}

	return publicBuckets, nil
}

// CheckOpenSecurityGroups finds security groups with risky ports exposed to the internet
func (s *SecurityAuditor) CheckOpenSecurityGroups(ctx context.Context) ([]OpenSecurityGroup, error) {
	// Get all security groups
	result, err := s.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	openGroups := make([]OpenSecurityGroup, 0)

	for _, sg := range result.SecurityGroups {
		groupID := aws.ToString(sg.GroupId)
		groupName := aws.ToString(sg.GroupName)

		// Check ingress rules
		for _, permission := range sg.IpPermissions {
			findings := evaluateSecurityGroupRule(permission, groupID, groupName)
			openGroups = append(openGroups, findings...)
		}
	}

	return openGroups, nil
}

// evaluateSecurityGroupRule checks if a security group rule exposes risky ports
func evaluateSecurityGroupRule(permission ec2types.IpPermission, groupID, groupName string) []OpenSecurityGroup {
	findings := make([]OpenSecurityGroup, 0)

	fromPort := aws.ToInt32(permission.FromPort)
	toPort := aws.ToInt32(permission.ToPort)
	protocol := aws.ToString(permission.IpProtocol)

	// Check IPv4 ranges
	for _, ipRange := range permission.IpRanges {
		cidr := aws.ToString(ipRange.CidrIp)
		if IsPublicCIDR(cidr) {
			portFindings := checkPortRange(fromPort, toPort, protocol, cidr, groupID, groupName)
			findings = append(findings, portFindings...)
		}
	}

	// Check IPv6 ranges
	for _, ipv6Range := range permission.Ipv6Ranges {
		cidr := aws.ToString(ipv6Range.CidrIpv6)
		if IsPublicCIDR(cidr) {
			portFindings := checkPortRange(fromPort, toPort, protocol, cidr, groupID, groupName)
			findings = append(findings, portFindings...)
		}
	}

	return findings
}

// checkPortRange checks if a port range includes any risky ports
func checkPortRange(fromPort, toPort int32, protocol, source, groupID, groupName string) []OpenSecurityGroup {
	findings := make([]OpenSecurityGroup, 0)

	// Handle "all traffic" rule (protocol -1)
	if protocol == "-1" {
		// All traffic means all ports are open
		for port, _ := range RiskyPorts {
			findings = append(findings, OpenSecurityGroup{
				GroupID:   groupID,
				GroupName: groupName,
				Port:      port,
				Protocol:  "ALL",
				Source:    source,
				Severity:  GetPortSeverity(port),
			})
		}
		return findings
	}

	// Check each risky port
	for port := range RiskyPorts {
		if IsPortInRange(port, fromPort, toPort) {
			findings = append(findings, OpenSecurityGroup{
				GroupID:   groupID,
				GroupName: groupName,
				Port:      port,
				Protocol:  normalizeProtocol(protocol),
				Source:    source,
				Severity:  GetPortSeverity(port),
			})
		}
	}

	return findings
}

// IsPublicCIDR checks if a CIDR block represents public/unrestricted access
func IsPublicCIDR(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// IsPortInRange checks if a specific port falls within a port range
func IsPortInRange(port, fromPort, toPort int32) bool {
	// Handle case where from/to are both 0 (all ports for ICMP or similar)
	if fromPort == 0 && toPort == 0 {
		return false
	}
	return port >= fromPort && port <= toPort
}

// GetPortSeverity returns the severity level for a given risky port
func GetPortSeverity(port int32) Severity {
	switch port {
	case 22, 3389: // SSH, RDP - direct remote access
		return SeverityCritical
	case 3306, 5432, 27017: // Database ports
		return SeverityCritical
	default:
		return SeverityHigh
	}
}

// IsRiskyPort checks if a port is in the risky ports list
func IsRiskyPort(port int32) bool {
	_, exists := RiskyPorts[port]
	return exists
}

// normalizeProtocol converts protocol numbers to readable names
func normalizeProtocol(protocol string) string {
	switch protocol {
	case "6", "tcp":
		return "TCP"
	case "17", "udp":
		return "UDP"
	case "-1":
		return "ALL"
	default:
		return protocol
	}
}

// GetSeverityColor returns ANSI color code for severity
func GetSeverityColor(severity Severity) string {
	switch severity {
	case SeverityCritical:
		return "\033[31m" // Red
	case SeverityHigh:
		return "\033[33m" // Yellow
	case SeverityMedium:
		return "\033[38;5;208m" // Orange (256 color)
	default:
		return "\033[0m"
	}
}

// ResetColor returns ANSI reset code
func ResetSecurityColor() string {
	return "\033[0m"
}

// CountBySeverity returns counts of findings by severity
func (r *SecurityResults) CountBySeverity() map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
	}

	for _, bucket := range r.PublicS3Buckets {
		counts[bucket.Severity]++
	}

	for _, sg := range r.OpenSecurityGroups {
		counts[sg.Severity]++
	}

	return counts
}
