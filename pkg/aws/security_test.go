package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestIsPublicCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{
			name:     "IPv4 all traffic",
			cidr:     "0.0.0.0/0",
			expected: true,
		},
		{
			name:     "IPv6 all traffic",
			cidr:     "::/0",
			expected: true,
		},
		{
			name:     "private IPv4 /24",
			cidr:     "10.0.0.0/24",
			expected: false,
		},
		{
			name:     "private IPv4 /16",
			cidr:     "172.16.0.0/16",
			expected: false,
		},
		{
			name:     "specific IP /32",
			cidr:     "203.0.113.5/32",
			expected: false,
		},
		{
			name:     "private IPv4 /8",
			cidr:     "192.168.0.0/8",
			expected: false,
		},
		{
			name:     "IPv6 specific range",
			cidr:     "2001:db8::/32",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPublicCIDR(tt.cidr)
			if got != tt.expected {
				t.Errorf("IsPublicCIDR(%q) = %v, want %v", tt.cidr, got, tt.expected)
			}
		})
	}
}

func TestIsPortInRange(t *testing.T) {
	tests := []struct {
		name     string
		port     int32
		fromPort int32
		toPort   int32
		expected bool
	}{
		{
			name:     "port exactly matches single port",
			port:     22,
			fromPort: 22,
			toPort:   22,
			expected: true,
		},
		{
			name:     "port within range",
			port:     443,
			fromPort: 1,
			toPort:   65535,
			expected: true,
		},
		{
			name:     "port at start of range",
			port:     100,
			fromPort: 100,
			toPort:   200,
			expected: true,
		},
		{
			name:     "port at end of range",
			port:     200,
			fromPort: 100,
			toPort:   200,
			expected: true,
		},
		{
			name:     "port outside range (below)",
			port:     22,
			fromPort: 80,
			toPort:   443,
			expected: false,
		},
		{
			name:     "port outside range (above)",
			port:     8080,
			fromPort: 80,
			toPort:   443,
			expected: false,
		},
		{
			name:     "ICMP rule (0-0) should not match",
			port:     22,
			fromPort: 0,
			toPort:   0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPortInRange(tt.port, tt.fromPort, tt.toPort)
			if got != tt.expected {
				t.Errorf("IsPortInRange(%d, %d, %d) = %v, want %v",
					tt.port, tt.fromPort, tt.toPort, got, tt.expected)
			}
		})
	}
}

func TestIsRiskyPort(t *testing.T) {
	tests := []struct {
		name     string
		port     int32
		expected bool
	}{
		{
			name:     "SSH port 22",
			port:     22,
			expected: true,
		},
		{
			name:     "RDP port 3389",
			port:     3389,
			expected: true,
		},
		{
			name:     "MySQL port 3306",
			port:     3306,
			expected: true,
		},
		{
			name:     "PostgreSQL port 5432",
			port:     5432,
			expected: true,
		},
		{
			name:     "MongoDB port 27017",
			port:     27017,
			expected: true,
		},
		{
			name:     "HTTP port 80 not risky",
			port:     80,
			expected: false,
		},
		{
			name:     "HTTPS port 443 not risky",
			port:     443,
			expected: false,
		},
		{
			name:     "random high port not risky",
			port:     8080,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRiskyPort(tt.port)
			if got != tt.expected {
				t.Errorf("IsRiskyPort(%d) = %v, want %v", tt.port, got, tt.expected)
			}
		})
	}
}

func TestGetPortSeverity(t *testing.T) {
	tests := []struct {
		name     string
		port     int32
		expected Severity
	}{
		{
			name:     "SSH is critical",
			port:     22,
			expected: SeverityCritical,
		},
		{
			name:     "RDP is critical",
			port:     3389,
			expected: SeverityCritical,
		},
		{
			name:     "MySQL is critical",
			port:     3306,
			expected: SeverityCritical,
		},
		{
			name:     "PostgreSQL is critical",
			port:     5432,
			expected: SeverityCritical,
		},
		{
			name:     "MongoDB is critical",
			port:     27017,
			expected: SeverityCritical,
		},
		{
			name:     "unknown port defaults to high",
			port:     8080,
			expected: SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPortSeverity(tt.port)
			if got != tt.expected {
				t.Errorf("GetPortSeverity(%d) = %v, want %v", tt.port, got, tt.expected)
			}
		})
	}
}

func TestEvaluateSecurityGroupRule(t *testing.T) {
	tests := []struct {
		name       string
		permission ec2types.IpPermission
		groupID    string
		groupName  string
		wantCount  int
		wantPorts  []int32
	}{
		{
			name: "SSH open to internet",
			permission: ec2types.IpPermission{
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpProtocol: aws.String("tcp"),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			groupID:   "sg-123",
			groupName: "test-sg",
			wantCount: 1,
			wantPorts: []int32{22},
		},
		{
			name: "SSH restricted to private IP",
			permission: ec2types.IpPermission{
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpProtocol: aws.String("tcp"),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("10.0.0.0/8")},
				},
			},
			groupID:   "sg-123",
			groupName: "test-sg",
			wantCount: 0,
			wantPorts: nil,
		},
		{
			name: "multiple risky ports in range",
			permission: ec2types.IpPermission{
				FromPort:   aws.Int32(1),
				ToPort:     aws.Int32(65535),
				IpProtocol: aws.String("tcp"),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			groupID:   "sg-456",
			groupName: "wide-open",
			wantCount: 5, // SSH, RDP, MySQL, PostgreSQL, MongoDB
			wantPorts: []int32{22, 3389, 3306, 5432, 27017},
		},
		{
			name: "IPv6 public access to MySQL",
			permission: ec2types.IpPermission{
				FromPort:   aws.Int32(3306),
				ToPort:     aws.Int32(3306),
				IpProtocol: aws.String("tcp"),
				Ipv6Ranges: []ec2types.Ipv6Range{
					{CidrIpv6: aws.String("::/0")},
				},
			},
			groupID:   "sg-789",
			groupName: "mysql-sg",
			wantCount: 1,
			wantPorts: []int32{3306},
		},
		{
			name: "all traffic rule (-1 protocol)",
			permission: ec2types.IpPermission{
				FromPort:   aws.Int32(0),
				ToPort:     aws.Int32(0),
				IpProtocol: aws.String("-1"),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			groupID:   "sg-all",
			groupName: "all-traffic",
			wantCount: 5, // All risky ports flagged
			wantPorts: []int32{22, 3389, 3306, 5432, 27017},
		},
		{
			name: "HTTPS port - not risky",
			permission: ec2types.IpPermission{
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpProtocol: aws.String("tcp"),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			groupID:   "sg-web",
			groupName: "web-sg",
			wantCount: 0,
			wantPorts: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := evaluateSecurityGroupRule(tt.permission, tt.groupID, tt.groupName)

			if len(findings) != tt.wantCount {
				t.Errorf("evaluateSecurityGroupRule() returned %d findings, want %d",
					len(findings), tt.wantCount)
			}

			if tt.wantPorts != nil {
				foundPorts := make(map[int32]bool)
				for _, f := range findings {
					foundPorts[f.Port] = true
				}

				for _, wantPort := range tt.wantPorts {
					if !foundPorts[wantPort] {
						t.Errorf("expected to find port %d in findings", wantPort)
					}
				}
			}

			// Verify all findings have correct group info
			for _, f := range findings {
				if f.GroupID != tt.groupID {
					t.Errorf("finding GroupID = %q, want %q", f.GroupID, tt.groupID)
				}
				if f.GroupName != tt.groupName {
					t.Errorf("finding GroupName = %q, want %q", f.GroupName, tt.groupName)
				}
			}
		})
	}
}

func TestSecurityResultsCountBySeverity(t *testing.T) {
	results := &SecurityResults{
		PublicS3Buckets: []PublicS3Bucket{
			{BucketName: "bucket1", Severity: SeverityCritical},
			{BucketName: "bucket2", Severity: SeverityCritical},
		},
		OpenSecurityGroups: []OpenSecurityGroup{
			{GroupID: "sg-1", Port: 22, Severity: SeverityCritical},
			{GroupID: "sg-2", Port: 8080, Severity: SeverityHigh},
			{GroupID: "sg-3", Port: 8081, Severity: SeverityHigh},
			{GroupID: "sg-4", Port: 8082, Severity: SeverityMedium},
		},
	}

	counts := results.CountBySeverity()

	if counts[SeverityCritical] != 3 {
		t.Errorf("Critical count = %d, want 3", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 2 {
		t.Errorf("High count = %d, want 2", counts[SeverityHigh])
	}
	if counts[SeverityMedium] != 1 {
		t.Errorf("Medium count = %d, want 1", counts[SeverityMedium])
	}
}

func TestGetSeverityColor(t *testing.T) {
	tests := []struct {
		severity Severity
		wantCode string
	}{
		{SeverityCritical, "\033[31m"},
		{SeverityHigh, "\033[33m"},
		{SeverityMedium, "\033[38;5;208m"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := GetSeverityColor(tt.severity)
			if got != tt.wantCode {
				t.Errorf("GetSeverityColor(%s) = %q, want %q", tt.severity, got, tt.wantCode)
			}
		})
	}
}

func TestNormalizeProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"tcp", "TCP"},
		{"6", "TCP"},
		{"udp", "UDP"},
		{"17", "UDP"},
		{"-1", "ALL"},
		{"icmp", "icmp"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeProtocol(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeProtocol(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
