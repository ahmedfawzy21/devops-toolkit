# dtk — DevOps Toolkit

**A read-only AWS + Kubernetes cost and security auditor in a single Go binary.** One tool that covers more ground than a typical single-purpose scanner: cloud cost waste, EKS-layer cost intelligence, and deep security auditing across IAM, Lambda, RDS, secrets, IMDS, and EKS — every check a read-only API call that never touches your resources.

[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8?logo=go)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/ahmedfawzy21/devops-toolkit)](https://goreportcard.com/report/github.com/ahmedfawzy21/devops-toolkit)

---

## Why this exists

This tool grew out of running 15+ microservices on AWS EKS in production. The day-to-day
reality there is that cost waste and security drift accumulate in the gaps *between*
tools: Cost Explorer gives you a number but not which node group is 90% On-Demand; a cost
scanner finds idle EBS volumes but says nothing about a Lambda with a public URL or an RDS
instance running an end-of-life engine; `kubectl` shows you pods but not which ones ship
with no memory limit and will get OOMKilled under load.

`dtk` is the tool I wanted: one binary I could point at an account (or a cluster) and get
an honest, prioritized list of what's wasting money and what's a security risk — without
ever worrying it might *change* something. Every command is a `Describe` / `List` / `Get`
call. It reads; it never writes.

In production use it has helped reclaim roughly **[VERIFY: exact $ figure]/month** in
recurring AWS spend and cut audit MTTR from **[VERIFY: exact before/after figure]**.
*(These are placeholders — replace them with your own measured numbers before publishing;
they are intentionally not fabricated here.)*

---

## Installation

### 1. Homebrew (recommended, once the tap is live)

```bash
brew install ahmedfawzy21/tap/devops-toolkit
```

### 2. go install

```bash
go install github.com/ahmedfawzy21/devops-toolkit@latest
```

> Requires Go 1.24+. Installs the `dtk` binary into `$(go env GOPATH)/bin`.

### 3. Build from source

```bash
git clone https://github.com/ahmedfawzy21/devops-toolkit.git
cd devops-toolkit
go build -o dtk .
./dtk --version
```

---

## Quickstart

The single most useful first command — a full cost-waste audit of a region:

```bash
dtk aws audit --regions us-east-1
```

Example output *(illustrative — not real account data)*:

```
🔍 Auditing AWS resources in regions: us-east-1

═══ Region: us-east-1 ═══

📦 Unattached EBS Volumes
─────────────────────────────────────────────────────────────
  VOLUME ID          SIZE (GB)  TYPE  AZ           AGE (DAYS)  MONTHLY COST
  vol-0abc123def45   100        gp3   us-east-1a   45          $8.00
  vol-0xyz789abc12   50         gp2   us-east-1b   120         $5.00

💻 Underutilized EC2 Instances (< 5% CPU)
─────────────────────────────────────────────────────────────
  i-0aa11bb22cc33    t3.large   2.10%   running    88          $60.00

💰 Potential Monthly Savings
─────────────────────────────────────────────────────────────
Total: $127.50

💡 Annual savings potential: $1,530.00
```

Add `--format json` for machine-readable output, or `--slack-webhook <url> --alert-threshold 100`
to post the summary to Slack only when savings clear a threshold.

---

## Feature matrix

Every subcommand below is implemented today. All are read-only.

### 💸 AWS Cost & Waste Audit — `dtk aws …`

| Command | What it checks | Example finding |
|---|---|---|
| `dtk aws audit` | Unattached EBS volumes, <5% CPU EC2, orphaned snapshots, unused Elastic IPs, <10% CPU RDS (opt-in: log groups, DynamoDB) | `vol-0abc… unattached — $8.00/mo` |
| `dtk aws security` | Public S3 buckets (ACL / disabled block-public-access), security groups exposing risky ports (22, 3389, 3306, 5432, 27017) to `0.0.0.0/0` | `sg-0f12… port 22 open to 0.0.0.0/0 — CRITICAL` |

### 📊 Cost Intelligence — `dtk cost …`

| Command | What it checks | Example finding |
|---|---|---|
| `dtk cost report` | Cost Explorer spend by `SERVICE` / `REGION` / `INSTANCE_TYPE` with daily trend and top-N | `Amazon EC2 — $1,234.56 (43.4%)` |
| `dtk cost loggroups` | CloudWatch log groups with no retention policy or no ingestion in 30 days | `/aws/lambda/old-fn — no retention, $3.20/mo` |
| `dtk cost dynamodb` | Tables without Point-in-Time Recovery; overprovisioned provisioned-capacity tables (<20% used) | `orders — provisioned 100 RCU, using 4 — $47/mo waste` |
| `dtk cost savings` | Reserved Instance & Compute Savings Plan purchase recommendations (1yr, No Upfront) | `m5.large ×3 — est. $210/mo savings` |

### ☸️ EKS Layer — `dtk eks …`

| Command | What it checks | Example finding |
|---|---|---|
| `dtk eks nodes` | Underutilized worker nodes (7-day avg CPU **and** memory < 30%) via Container Insights, with a rightsizing suggestion | `ip-10-0-1-5 — 12% CPU / 18% mem — downsize m5.xlarge → m5.large` |
| `dtk eks pods` | Containers missing CPU/memory requests or limits, with the practical risk | `web/api — no memory limit: at risk of OOMKill` |
| `dtk eks namespaces` | Cluster node cost allocated per namespace by reserved-capacity share | `payments — $312/mo (34% of cluster)` |
| `dtk eks nodegroups` | Spot vs On-Demand mix per node group, with a rebalance savings estimate | `default — 100% On-Demand — est. $180/mo if rebalanced` |
| `dtk eks audit` | Combined EKS audit (pods + node groups always; nodes + namespaces opt-in) with rolled-up savings | `Total potential savings: $360/mo` |

### 🔐 Security Scanner — `dtk security …`

| Command | What it checks | Example finding |
|---|---|---|
| `dtk security imds` | EC2 instances still allowing IMDSv1 (`HttpTokens != required`) — the SSRF credential-theft vector | `i-0aa11… IMDSv1 allowed — enforce IMDSv2` |
| `dtk security lambda` | Deprecated/EOL runtimes, Function URLs with `AuthType NONE`, over-provisioned memory | `checkout — runtime python3.7 deprecated` |
| `dtk security iam` | Console users without MFA, active access keys > 90 days, admin-equivalent (esp. unused) roles | `deploy-user — password set, MFA inactive` |
| `dtk security secrets` | Plaintext secrets in SSM `String` params and Lambda env var **keys** (names only, never values) | `/prod/DB_PASSWORD — plaintext SSM String` |
| `dtk security eks` | Clusters with a fully-public API endpoint (`0.0.0.0/0`), pods running/allowed as root, clusters below min supported version | `prod-cluster — API endpoint open to 0.0.0.0/0` |
| `dtk security rds` | Unencrypted storage, public access, no backups/deletion protection, EOL engines, insecure params, single-AZ prod, default usernames, public snapshots (MySQL + PostgreSQL) — **exits non-zero on any critical finding** | `orders-db — storage not encrypted at rest — CRITICAL` |
| `dtk security audit` | Runs every security check above and prints a combined report (a failing domain warns and continues) | combined IMDS + Lambda + IAM + Secrets + EKS + RDS report |

### 🏥 Kubernetes Health — `dtk k8s …`

| Command | What it checks | Example finding |
|---|---|---|
| `dtk k8s health` | Pod status, deployment readiness, node status/capacity, warning events (last hour) | `payments/api-7f… CrashLoopBackOff, 14 restarts` |
| `dtk k8s certs` | `kubernetes.io/tls` secrets, certificate expiry, colour-coded by urgency | `ingress-tls — expires in 5 days 🔴` |
| `dtk k8s pdb` | PodDisruptionBudgets: zero disruptions allowed, no matching pods, unhealthy pods | `web-pdb — 0 disruptions allowed — at-risk` |

---

## What makes this different

- **EKS-layer cost intelligence, not just account-level.** Most cost scanners stop at
  EC2/EBS/RDS. `dtk` goes a layer deeper: it rightsizes worker nodes from Container
  Insights utilization, flags pods with no resource limits before they cause an outage,
  attributes cluster spend per namespace, and reports each node group's Spot/On-Demand
  balance with a rebalance savings estimate.
- **Security scanning that goes well beyond cost.** IMDSv2 enforcement, IAM credential
  analysis (MFA, key age, admin roles derived from the actual policy documents),
  plaintext-secret discovery, and full RDS posture checks for **both MySQL and
  PostgreSQL** — not just the "idle resource" checks a cost tool gives you.
- **Read-only by design.** This tool never modifies or deletes anything. Every check is a
  `Describe` / `List` / `Get` API call (the sole exception is IAM
  `GenerateCredentialReport`, which produces a read-only credential report and changes no
  resource). There is no code path in this repository that creates, updates, deletes, or
  terminates a cloud resource — verified across `pkg/aws/` and `pkg/eks/`. You can run it
  against production without a change-management ticket.
- **One binary, one mental model.** AWS, EKS, and Kubernetes checks share the same
  finding/report pipeline, the same `--format table|json` output, and the same optional
  Slack alerting — so wiring any check into CI is identical.

---

## Requirements

- **Go 1.24+** — only to build from source or `go install`; Homebrew/release binaries are self-contained.
- **AWS credentials** for the `aws`, `cost`, `eks`, and `security` commands, resolved via
  the standard AWS chain (environment variables, `~/.aws/credentials`, or an instance/IRSA
  role). Region resolves from `--region`/`--regions`, then `$AWS_REGION`, then `us-east-1`.
  - The tool needs only read-only IAM permissions (`Describe*` / `List*` / `Get*` on the
    relevant services, plus `iam:GenerateCredentialReport`). A sample read-only IAM policy
    may be added to this repo in a later phase.
- **kubeconfig** for the `k8s` commands and the Kubernetes-facing `eks` checks (`eks pods`,
  and the pod checks within `eks audit` / `security eks`). The tool reads `~/.kube/config`
  and uses the current context.
- **CloudWatch Container Insights** enabled on the cluster for `eks nodes` and
  `eks namespaces` (the tool prints exact enablement steps if it's missing).

---

## Contributing

Contributions are welcome. This is a standard Go project — please:

- Follow standard Go conventions (`gofmt`, `go vet`).
- Keep the read-only guarantee intact: no `Create` / `Delete` / `Modify` / `Put` API calls.
- Include tests. The suite must pass before a PR is merged:

  ```bash
  go test ./...
  ```

- Prefer small, pure, testable rule functions (see the existing `*_test.go` files for the pattern).

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Ahmed Fawzy.
