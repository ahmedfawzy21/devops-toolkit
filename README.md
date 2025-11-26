# DevOps Toolkit (dtk)

A production-grade CLI toolkit for DevOps engineers, built in Go. Provides essential utilities for AWS resource auditing, Kubernetes health checking, and cost analysis.

## Features

### 🔍 AWS Resource Auditing
- **Multi-region scanning** - Audit multiple AWS regions simultaneously
- **EBS volumes** - Find unattached volumes and calculate storage waste
- **EC2 instances** - Identify underutilized instances (< 5% CPU over 7 days)
- **RDS databases** - Detect underutilized RDS instances (< 10% CPU)
- **EBS snapshots** - Find orphaned snapshots from deleted volumes
- **Elastic IPs** - Identify unused/unattached Elastic IPs
- **Cost analysis** - Calculate potential monthly savings across all resources
- **Slack notifications** - Real-time alerts for cost-saving opportunities

### 🏥 Kubernetes Operations
- **Health checks** - Comprehensive pod, deployment, and node status
- **Certificate monitoring** - TLS certificate expiry tracking with configurable thresholds
- **PodDisruptionBudget monitoring** - Detect at-risk PDBs and misconfigured disruption budgets
- **Multi-namespace support** - Scan all namespaces or target specific ones
- **Color-coded output** - Visual status indicators (🔴 critical, 🟡 warning, 🟢 healthy)
- **Slack alerts** - Proactive notifications for certificates and PDB issues

### 📢 Alerting & Notifications
- **Slack webhook integration** - Real-time alerts to Slack channels
- **AWS audit alerts** - Configurable thresholds for cost savings notifications
- **Certificate expiry alerts** - Automated warnings for expiring TLS certificates
- **PDB health alerts** - Notifications for disruption budget issues
- **Color-coded severity** - Green (healthy), yellow (warning), red (critical)
- **Detailed findings** - Rich message formatting with resource counts and status

### 💰 AWS Cost Reporting
- **Time-based analysis** - Daily, weekly, or monthly spending trends
- **Multi-dimensional grouping** - Cost breakdown by service, region, or instance type
- **Top spenders** - Identify highest-cost resources
- **Trend comparison** - Month-over-month cost analysis
- **Budget tracking** - Monitor spending against targets

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

## Quick Start Examples

Get started quickly with these common usage patterns:

```bash
# Full AWS audit with Slack alerts for savings over $50
dtk aws audit --regions us-east-1,eu-west-1 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --alert-threshold 50

# Check Kubernetes certificates expiring within 14 days
dtk k8s certs --expiry-days 14

# Check PodDisruptionBudget status in production namespace
dtk k8s pdb --namespace production

# Combined Kubernetes health check
dtk k8s health && dtk k8s certs && dtk k8s pdb

# Multi-region AWS cost analysis
dtk cost report --days 30 --group-by SERVICE

# Production certificate monitoring with alerts
dtk k8s certs --namespace production \
  --expiry-days 7 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
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

## Alerting

### Slack Integration

Get real-time alerts for AWS cost findings, certificate expiry, and PodDisruptionBudget issues.

**Setup Slack Webhook:**
1. Go to your Slack workspace
2. Navigate to: Apps → [Incoming Webhooks](https://slack.com/apps/A0F7XDUAZ-incoming-webhooks)
3. Click "Add to Slack"
4. Choose a channel and click "Add Incoming Webhooks Integration"
5. Copy the webhook URL (format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX`)
6. Use the URL with `--slack-webhook` flag

**Color-Coded Alerts:**
- 🟢 **Green (Good)** - Low severity, healthy status
- 🟡 **Yellow (Warning)** - Medium severity, at-risk status
- 🔴 **Red (Danger)** - High severity, critical issues

**AWS Audit Alerts:**

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

The AWS audit Slack message includes:
- 📊 Resource counts with emoji icons
- 💰 Total potential monthly savings
- 🎨 Color-coded severity (green/yellow/red based on savings)
- ⏰ Timestamp of the audit
- 📋 Breakdown by resource type (EBS, EC2, RDS, Snapshots, EIPs)

**Example AWS Audit Slack Message:**
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

**Kubernetes Certificate Alerts:**

```bash
# Alert if any certificates expiring within 30 days
dtk k8s certs --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Alert for certificates expiring within 14 days in production namespace
dtk k8s certs --namespace production \
  --expiry-days 14 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

The certificate expiry Slack message includes:
- 🔐 List of expiring certificates with status
- 📅 Days remaining for each certificate
- 🎨 Color-coded severity (red: critical/expired, yellow: expiring soon, green: valid)
- 📊 Summary counts (total, critical, expiring, expired)

**Example Certificate Expiry Slack Message:**
```
🔐 Kubernetes TLS Certificate Expiry Alert
Found 3 TLS certificate(s) expiring within 30 days

🔴 EXPIRED default/old-cert - -5 days remaining (example.com)
🟠 CRITICAL production/api-cert - 3 days remaining (api.example.com, www.example.com)
🟡 EXPIRING SOON staging/web-cert - 25 days remaining (staging.example.com)

📅 Certificates Found: 3
⚠️ Critical (<7 days): 1
⏳ Expiring Soon (<30 days): 1
❌ Expired: 1
```


## Kubernetes Commands

### Health Check

Perform comprehensive health checks on your Kubernetes cluster.

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

**Example output:**
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

### Certificate Expiry Monitoring

Monitor TLS certificate expiration in your Kubernetes cluster to prevent service disruptions.

```bash
# Check all namespaces for certificates expiring within 30 days (default)
dtk k8s certs

# Check specific namespace
dtk k8s certs --namespace production

# Check for certificates expiring within 60 days
dtk k8s certs --expiry-days 60

# Check with Slack alerts
dtk k8s certs --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Combine flags for production monitoring
dtk k8s certs --namespace production \
  --expiry-days 14 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Flags:**
- `--namespace` / `-n`: Specific namespace to scan (default: all namespaces)
- `--expiry-days`: Show certificates expiring within N days (default: 30)
- `--slack-webhook`: Slack webhook URL for certificate expiry alerts

**Color Coding:**
- 🔴 **Red** - Expired or Critical (<7 days remaining)
- 🟡 **Yellow** - Expiring Soon (7-30 days remaining)
- 🟢 **Green** - Valid (>30 days remaining)

**Example output:**
```
🔐 Checking TLS certificate expiry in Kubernetes...

Scanning all namespaces for TLS certificates expiring within 30 days...

Found 4 certificate(s) expiring within 30 days (scanned 15 TLS secrets)

SECRET                         NAMESPACE            DAYS REMAINING  DNS NAMES                                EXPIRY DATE          STATUS
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
api-tls-cert                   production           3               api.example.com, www.example.com         2024-11-29 14:30     critical
ingress-tls                    default              15              *.example.com                            2024-12-11 10:20     expiring-soon
web-cert                       staging              25              staging.example.com                      2024-12-21 08:15     expiring-soon
old-cert                       default              -5              old.example.com                          2024-11-21 12:00     expired

🔴 Expired: 1
🟠 Critical (<7 days): 1
🟡 Expiring Soon (<30 days): 2
```

**What it checks:**
- Scans all `kubernetes.io/tls` type secrets
- Parses X.509 certificates from `tls.crt` data
- Extracts certificate metadata: DNS names, common name, expiry date
- Calculates days remaining until expiration
- Filters by expiry threshold (default 30 days)
- Sends Slack alerts if configured and certificates are expiring

**Use cases:**
- Proactive certificate renewal monitoring
- Prevent production outages due to expired certificates
- Compliance auditing for certificate lifecycle management
- Automated alerting in CI/CD pipelines

### PodDisruptionBudget Monitoring

Check the health status of PodDisruptionBudgets to ensure cluster resilience.

```bash
# Check all namespaces
dtk k8s pdb

# Check specific namespace
dtk k8s pdb --namespace production

# With Slack alerts for issues
dtk k8s pdb --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Flags:**
- `--namespace` / `-n`: Specific namespace to scan (default: all namespaces)
- `--slack-webhook`: Slack webhook URL for PDB health alerts

**Status Types:**
- 🟢 **Healthy** - Disruptions allowed > 0, all pods healthy
- 🟡 **At-Risk** - Zero disruptions allowed OR unhealthy pods
- 🔴 **Critical** - Zero disruptions allowed AND unhealthy pods
- ⚪ **No-Pods** - PDB has no matching pods (misconfigured selector)

**Example output:**
```
🛡️  Checking PodDisruptionBudget status...

Scanning all namespaces for PodDisruptionBudgets...

🛡️  PodDisruptionBudget Status
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
NAMESPACE            NAME                      MIN AVAIL       CURRENT    ALLOWED    STATUS
────────────────────┼─────────────────────────┼───────────────┼──────────┼──────────┼────────────────────────────────────
production           api-pdb                   2               3          1          🟢 healthy
production           web-pdb                   80%             2          0          🟡 at-risk
staging              db-pdb                    1               0          0          ⚪ no-pods

Summary:
✅ Healthy: 1
⚠️  At-Risk (0 disruptions allowed): 1
❌ No Matching Pods: 1
```

**What it checks:**
- Scans all PodDisruptionBudgets across namespaces
- Identifies PDBs with zero disruptions allowed (prevents safe evictions)
- Detects misconfigured PDBs with no matching pods
- Finds PDBs with unhealthy pods
- Sends Slack alerts for at-risk or critical PDBs

**Use cases:**
- Ensure safe cluster maintenance and node draining
- Prevent deployment issues due to restrictive PDBs
- Detect misconfigured disruption budgets
- Monitor application availability guarantees

## Cost Reporting

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

## Common Usage Examples

Here are some real-world usage examples combining different features:

### AWS Audit with Slack Alerts

```bash
# Basic audit with Slack notifications
dtk aws audit --regions eu-north-1 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Multi-region audit with alert threshold
dtk aws audit --regions us-east-1,us-west-2,eu-west-1 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --alert-threshold 100

# Targeted audit - only EBS and EC2 with JSON output
dtk aws audit --regions us-east-1 \
  --ebs --ec2 \
  --no-snapshots --no-eips --no-rds \
  --format json \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Kubernetes Certificate Monitoring

```bash
# Check all certificates expiring within 30 days
dtk k8s certs --expiry-days 30

# Production namespace with 14-day warning
dtk k8s certs --namespace production --expiry-days 14

# Production monitoring with Slack alerts
dtk k8s certs --namespace production \
  --expiry-days 14 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Critical alerts - only show certificates expiring within 7 days
dtk k8s certs --expiry-days 7 \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Scheduled Monitoring (Cron Jobs)

Set up automated monitoring with cron:

```bash
# Add to crontab (crontab -e)

# Daily AWS audit at 9 AM with Slack alerts
0 9 * * * /usr/local/bin/dtk aws audit --regions us-east-1 --slack-webhook https://hooks.slack.com/xxx --alert-threshold 50

# Weekly certificate check on Mondays at 8 AM
0 8 * * 1 /usr/local/bin/dtk k8s certs --expiry-days 30 --slack-webhook https://hooks.slack.com/xxx

# Hourly critical certificate check for production
0 * * * * /usr/local/bin/dtk k8s certs --namespace production --expiry-days 7 --slack-webhook https://hooks.slack.com/xxx
```

### CI/CD Pipeline Integration

```yaml
# Example GitHub Actions workflow
name: Infrastructure Audit
on:
  schedule:
    - cron: '0 9 * * *'  # Daily at 9 AM
  workflow_dispatch:

jobs:
  aws-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Run AWS Audit
        run: |
          dtk aws audit \
            --regions us-east-1,eu-west-1 \
            --slack-webhook ${{ secrets.SLACK_WEBHOOK }} \
            --alert-threshold 100

  k8s-cert-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check Certificate Expiry
        run: |
          dtk k8s certs \
            --expiry-days 30 \
            --slack-webhook ${{ secrets.SLACK_WEBHOOK }}
```

### Combined Monitoring Script

```bash
#!/bin/bash
# daily-audit.sh - Comprehensive infrastructure monitoring

SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

echo "Running AWS Audit..."
dtk aws audit \
  --regions us-east-1,us-west-2 \
  --slack-webhook "$SLACK_WEBHOOK" \
  --alert-threshold 50

echo "Checking Kubernetes certificates..."
dtk k8s certs \
  --expiry-days 30 \
  --slack-webhook "$SLACK_WEBHOOK"

echo "Checking Kubernetes health..."
dtk k8s health --all-namespaces

echo "Audit complete!"
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

### System Requirements
- **Go 1.21+** - Modern Go version with generics support
- **AWS credentials** - Configured via `~/.aws/credentials` or environment variables
- **kubectl** - Configured for Kubernetes operations (for k8s commands)

### Built With

**Core Technologies:**
- **Go 1.21+** - Primary programming language
- **Cobra** (`github.com/spf13/cobra`) - CLI framework and command structure
- **AWS SDK for Go v2** (`github.com/aws/aws-sdk-go-v2`) - AWS service integrations
- **Kubernetes client-go** (`k8s.io/client-go`) - Kubernetes API interactions

**AWS SDKs:**
- `aws-sdk-go-v2/service/ec2` - EC2 and EBS operations
- `aws-sdk-go-v2/service/rds` - RDS database monitoring
- `aws-sdk-go-v2/service/cloudwatch` - Metrics and monitoring
- `aws-sdk-go-v2/service/costexplorer` - Cost analysis and reporting

**Kubernetes SDKs:**
- `k8s.io/api/core/v1` - Core Kubernetes resources
- `k8s.io/api/apps/v1` - Deployments and workloads
- `k8s.io/api/policy/v1` - PodDisruptionBudgets

**Utilities:**
- `github.com/olekukonko/tablewriter` - Formatted table output
- Standard library `crypto/x509` - Certificate parsing
- Standard library `net/http` - Webhook integrations

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
