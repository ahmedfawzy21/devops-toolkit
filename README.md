# DevOps Toolkit (dtk)

A production-grade CLI toolkit for DevOps engineers, built in Go. Provides essential utilities for AWS resource auditing, Kubernetes health checking, and cost analysis.

## Features

### 🔍 AWS Resource Auditing
- Find unattached EBS volumes
- Identify underutilized EC2 instances (< 5% CPU)
- Detect orphaned EBS snapshots
- Calculate potential monthly savings
- Slack notifications for audit alerts

### 🏥 Kubernetes Health Checking
- Comprehensive pod status across namespaces
- Deployment health and readiness
- Node status and capacity
- Recent warning events

### 💰 AWS Cost Reporting
- Daily/weekly/monthly spending trends
- Cost breakdown by service, region, or instance type
- Top spending resources identification
- Month-over-month comparison

## Installation

### Prerequisites
- Go 1.21 or higher
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- kubectl configured for Kubernetes operations

### Build from source

```bash
# Clone the repository
git clone https://github.com/ahmedfawzy/devops-toolkit
cd devops-toolkit

# Download dependencies
go mod download

# Build the binary
go build -o dtk main.go

# Install to $GOPATH/bin
go install

# Or use the Makefile
make build
make install
```

### Quick start

```bash
# Build and run
make run

# Or directly
./dtk --help
```

## Usage

### AWS Resource Audit

```bash
# Audit all resources in default region
dtk aws audit

# Audit specific region
dtk aws audit --region us-west-2

# Audit only EBS volumes
dtk aws audit --ebs --no-ec2 --no-snapshots

# Output as JSON
dtk aws audit --format json

# Output as CSV
dtk aws audit --format csv

# Send Slack alerts when savings are found
dtk aws audit --slack-webhook https://hooks.slack.com/services/xxx --alert-threshold 10

# Audit multiple regions with Slack notifications
dtk aws audit --regions us-east-1,us-west-2,eu-west-1 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --alert-threshold 100
```

Example output:
```
🔍 Auditing AWS resources in region: us-east-1

📦 Checking EBS volumes...
💻 Checking EC2 instances...
📸 Checking EBS snapshots...

📦 Unattached EBS Volumes
─────────────────────────────────────────────────────────────
VOLUME ID          SIZE (GB)  TYPE  AZ           AGE (DAYS)  MONTHLY COST
vol-0abc123def45   100        gp3   us-east-1a   45          $8.00
vol-0xyz789abc12   50         gp2   us-east-1b   120         $5.00

💰 Potential Monthly Savings
─────────────────────────────────────────────────────────────
Total: $127.50

💡 Annual savings potential: $1,530.00
```

#### Slack Integration

Get real-time alerts when cost-saving opportunities are detected:

```bash
# Send alert for any savings amount (threshold = 0)
dtk aws audit --regions us-east-1 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Only alert if savings exceed $100/month
dtk aws audit --regions us-east-1,us-west-2 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --alert-threshold 100

# Combine with other flags
dtk aws audit --regions eu-west-1 \
  --format json \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --alert-threshold 50 \
  --no-snapshots
```

The Slack message includes:
- 📊 Resource counts with emoji icons
- 💰 Total potential monthly savings
- 🎨 Color-coded severity (green/yellow/red based on savings)
- ⏰ Timestamp of the audit
- 📋 Breakdown by resource type (EBS, EC2, RDS, Snapshots, EIPs)

**Example Slack message:**
```
🔍 AWS DevOps Audit Report
AWS audit completed for regions: us-east-1, us-west-2

📦 Unattached EBS Volumes: 5 (Est. $45.00/mo)
💻 Underutilized EC2 Instances: 2 (Est. $100.00/mo)
🗄️  Underutilized RDS Instances: 1 (Est. $145.00/mo)
📸 Orphaned Snapshots: 12 (Est. $25.00/mo)
🌐 Unused Elastic IPs: 3 (Est. $10.80/mo)

💰 Total Potential Savings: $325.80/month
📅 Timestamp: 2024-11-26 15:30:45 UTC
📋 Total Resources Found: 23
```

**Setup Slack webhook:**
1. Go to your Slack workspace
2. Navigate to: Apps → Incoming Webhooks
3. Click "Add to Slack"
4. Choose a channel and click "Add Incoming Webhooks Integration"
5. Copy the webhook URL
6. Use the URL with `--slack-webhook` flag

```

### Kubernetes Health Check

```bash
# Check all namespaces
dtk k8s health

# Check specific namespace
dtk k8s health --namespace production

# Check without node status
dtk k8s health --nodes=false

# Output as JSON
dtk k8s health --format json
```

Example output:
```
🏥 Checking Kubernetes cluster health...

🔍 Checking pods...
📦 Checking deployments...
🖥️  Checking nodes...
📋 Checking recent events...

🔵 Pods Status
─────────────────────────────────────────────────────────────
NAMESPACE   NAME                    READY  STATUS   RESTARTS  AGE
default     nginx-abc123            1/1    Running  0         2d5h
default     redis-xyz789            1/1    Running  3         5d12h

📦 Deployments Status
─────────────────────────────────────────────────────────────
NAMESPACE   NAME    READY  UP-TO-DATE  AVAILABLE  AGE
default     nginx   3/3    3           3          15d

✅ No warning events in the last hour
```

### Cost Reporting

```bash
# Last 7 days cost report
dtk cost report

# Last 30 days by service
dtk cost report --days 30 --group-by SERVICE

# Last 90 days by region
dtk cost report --days 90 --group-by REGION

# Show top 5 spending items
dtk cost report --top 5

# Output as JSON
dtk cost report --format json
```

Example output:
```
💰 Generating cost report for last 7 days...

📅 Period: 2024-11-07 to 2024-11-14
🏷️  Grouping: SERVICE

📊 Cost Report (2024-11-07 to 2024-11-14)
─────────────────────────────────────────────────────────────
Total Cost: $2,847.32 USD

💵 Cost Breakdown by SERVICE
─────────────────────────────────────────────────────────────
SERVICE                          COST        % OF TOTAL
Amazon Elastic Compute Cloud     $1,234.56   43.4%
Amazon Relational Database       $876.54     30.8%
Amazon Simple Storage Service    $345.67     12.1%
Amazon CloudWatch               $123.45     4.3%
Other                           $267.10     9.4%
```

## Configuration

### AWS Configuration

Ensure AWS credentials are configured:

```bash
# Using AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

### Kubernetes Configuration

Ensure kubectl is configured:

```bash
# Verify connection
kubectl cluster-info

# Set default namespace (optional)
kubectl config set-context --current --namespace=production
```

## Development

### Project Structure

```
devops-toolkit/
├── cmd/                    # CLI commands
│   ├── root.go            # Root command
│   ├── aws.go             # AWS audit command
│   ├── k8s.go             # Kubernetes health command
│   └── cost.go            # Cost reporting command
├── pkg/                    # Core packages
│   ├── aws/               # AWS SDK operations
│   │   ├── auditor.go     # Resource auditing
│   │   ├── rds.go         # RDS auditing
│   │   └── cost.go        # Cost analysis
│   ├── k8s/               # Kubernetes operations
│   │   └── health.go      # Health checking
│   ├── notify/            # Notification integrations
│   │   └── slack.go       # Slack webhook alerts
│   └── reporter/          # Output formatting
│       └── reporter.go    # Table/JSON/CSV rendering
├── main.go                # Entry point
├── go.mod                 # Go modules
├── Makefile              # Build automation
└── README.md             # This file
```

### Build Commands

```bash
# Install dependencies
make deps

# Build binary
make build

# Run tests
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Install to $GOPATH/bin
make install
```

### Adding New Features

1. Add command in `cmd/` directory
2. Implement logic in `pkg/` directory
3. Register command in `cmd/root.go`
4. Add tests
5. Update README

## Requirements

### Go Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/aws/aws-sdk-go-v2` - AWS SDK
- `k8s.io/client-go` - Kubernetes client
- `github.com/olekukonko/tablewriter` - Table formatting

### AWS Permissions

Required IAM permissions for full functionality:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "cloudwatch:GetMetricStatistics",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

### Kubernetes Permissions

Required RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: devops-toolkit-reader
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "events"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list"]
```

## Roadmap

### Completed Features
- [x] Slack notifications for cost alerts

### Planned Features
- [ ] Multi-cloud support (Azure, GCP)
- [ ] Microsoft Teams notifications
- [ ] Prometheus metrics export
- [ ] Historical trend analysis
- [ ] Automated remediation suggestions
- [ ] CI/CD pipeline integration
- [ ] Docker image distribution

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Author

**Ahmed Fawzy Meselhy**
- Email: ahmed.fawzy21@gmail.com
- GitHub: [@ahmedfawzy](https://github.com/ahmedfawzy)
- Role: Senior DevOps/SRE Engineer

## Acknowledgments

Built as part of a DevOps learning journey, focusing on:
- Go programming language proficiency
- Cloud cost optimization (FinOps)
- Kubernetes operations at scale
- Infrastructure automation

---

**Note**: This tool is designed for DevOps engineers who need quick insights into their AWS and Kubernetes infrastructure. Always review recommendations before taking action on production systems.
