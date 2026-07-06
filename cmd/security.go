package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
	"github.com/ahmedfawzy/devops-toolkit/pkg/eks"
	"github.com/ahmedfawzy/devops-toolkit/pkg/reporter"
	"github.com/spf13/cobra"
)

var (
	secRegion    string
	secCluster   string
	secNamespace string
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Advanced AWS and EKS security scanning",
	Long:  "Scan AWS and EKS for security findings: IMDSv1 exposure, Lambda risks, IAM weaknesses, plaintext secrets, and EKS cluster/workload hardening",
	// Findings come from live AWS/Kubernetes calls; on a runtime failure the
	// actionable error is more useful than a cobra usage dump.
	SilenceUsage: true,
}

var securityIMDSCmd = &cobra.Command{
	Use:   "imds",
	Short: "Find EC2 instances still allowing IMDSv1",
	Long: `Scan running EC2 instances for Instance Metadata Service v1 exposure:

- Flags instances whose MetadataOptions do not require IMDSv2 (HttpTokens != required)
- IMDSv1 lets SSRF attacks steal IAM credentials from the metadata service

Example:
  dtk security imds --region us-east-1
  dtk security imds --region eu-west-1 --format json`,
	RunE: runSecurityIMDS,
}

var securityLambdaCmd = &cobra.Command{
	Use:   "lambda",
	Short: "Find Lambda security and cost issues",
	Long: `Scan Lambda functions for security and cost issues:

- Deprecated (or EOL-announced) runtimes that no longer receive patches
- Function URLs configured with AuthType NONE (unauthenticated public invoke)
- Over-provisioned memory (>= 512MB, short-running, low-traffic)

Example:
  dtk security lambda --region us-east-1
  dtk security lambda --region eu-west-1 --format json`,
	RunE: runSecurityLambda,
}

var securityIAMCmd = &cobra.Command{
	Use:   "iam",
	Short: "Deep IAM analysis",
	Long: `Analyze IAM for common weaknesses:

- Console users without MFA (from the account credential report)
- Active access keys older than 90 days
- Roles with admin-equivalent permissions, especially unused ones

IAM is global; the region flag is accepted for consistency but not significant.

Example:
  dtk security iam
  dtk security iam --format json`,
	RunE: runSecurityIAM,
}

var securitySecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Find plaintext secrets",
	Long: `Scan for secrets stored in plaintext:

- SSM String parameters (not SecureString) whose names look like secrets
- Lambda environment variable keys that look like secrets

Only names/keys are ever reported — never the underlying values.

Example:
  dtk security secrets --region us-east-1
  dtk security secrets --region eu-west-1 --format json`,
	RunE: runSecuritySecrets,
}

var securityEKSCmd = &cobra.Command{
	Use:   "eks",
	Short: "EKS cluster and workload security",
	Long: `Scan EKS for cluster- and workload-level security issues:

- Clusters with a fully-public API endpoint (0.0.0.0/0)
- Pods (or their containers) running, or permitted to run, as root
- Clusters below the minimum supported Kubernetes version

The endpoint and version checks scan every cluster in the account; the
pods-as-root check uses your local kubeconfig context. --cluster is optional
and only labels the output.

Example:
  dtk security eks --region us-east-1
  dtk security eks --cluster my-cluster --namespace production --format json`,
	RunE: runSecurityEKS,
}

var securityRDSCmd = &cobra.Command{
	Use:   "rds",
	Short: "RDS MySQL/PostgreSQL security posture checks",
	Long: `Scan RDS instances and manual snapshots for security issues:

- Unencrypted storage at rest
- Publicly accessible instances
- Automated backups disabled / no deletion protection
- End-of-life engine versions
- Insecure parameter-group settings (local_infile, general_log, ssl, log_connections)
- Single-AZ production instances and default master usernames
- Manual snapshots shared publicly (restorable by any AWS account)

Exits non-zero if any critical findings are found, so it can gate a CI/CD pipeline.

Note: the snapshot visibility check makes one API call per snapshot; may be slow
on accounts with many snapshots.

Example:
  dtk security rds --region us-east-1
  dtk security rds --region eu-west-1 --format json`,
	RunE: runSecurityRDS,
}

var securityAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run the full security audit",
	Long: `Run every security check and print a combined report:

- IMDSv1 exposure
- Lambda deprecated runtimes, public URLs, and over-provisioning
- IAM MFA, old access keys, and over-permissioned roles
- Plaintext secrets in SSM and Lambda env vars
- EKS public endpoints, root pods, and outdated versions

A failure in one domain prints a warning and the audit continues with the rest.
--cluster is optional and only labels the output.

Example:
  dtk security audit --region us-east-1
  dtk security audit --cluster my-cluster --region us-east-1 --format json`,
	RunE: runSecurityAudit,
}

func init() {
	rootCmd.AddCommand(securityCmd)
	securityCmd.AddCommand(securityIMDSCmd)
	securityCmd.AddCommand(securityLambdaCmd)
	securityCmd.AddCommand(securityIAMCmd)
	securityCmd.AddCommand(securitySecretsCmd)
	securityCmd.AddCommand(securityEKSCmd)
	securityCmd.AddCommand(securityRDSCmd)
	securityCmd.AddCommand(securityAuditCmd)

	securityIMDSCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securityIMDSCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	securityLambdaCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securityLambdaCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	securityIAMCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securityIAMCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	securitySecretsCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securitySecretsCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	securityEKSCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securityEKSCmd.Flags().StringVarP(&secCluster, "cluster", "c", "", "EKS cluster name for context in output (optional; endpoint/version checks scan all clusters)")
	securityEKSCmd.Flags().StringVar(&secNamespace, "namespace", "", "Kubernetes namespace for the pod check (default: all namespaces)")
	securityEKSCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	securityRDSCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securityRDSCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")

	securityAuditCmd.Flags().StringVarP(&secRegion, "region", "r", "", "AWS region")
	securityAuditCmd.Flags().StringVarP(&secCluster, "cluster", "c", "", "EKS cluster name for context in output (optional; endpoint/version checks scan all clusters)")
	securityAuditCmd.Flags().StringVar(&secNamespace, "namespace", "", "Kubernetes namespace for the pod check (default: all namespaces)")
	securityAuditCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
}

func resolveSecurityRegion() string {
	if secRegion != "" {
		return secRegion
	}
	if region := os.Getenv("AWS_REGION"); region != "" {
		return region
	}
	return "us-east-1"
}

func runSecurityIMDS(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	fmt.Printf("🔍 Scanning EC2 instances for IMDSv1 exposure in %s...\n\n", region)

	auditor, err := aws.NewIMDSAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create IMDS auditor: %w", err)
	}

	findings, err := auditor.FindInstancesWithIMDSv1(ctx)
	if err != nil {
		return fmt.Errorf("failed to find instances with IMDSv1: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderIMDSResults(findings); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runSecurityLambda(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	fmt.Printf("🔍 Scanning Lambda functions in %s...\n\n", region)

	auditor, err := aws.NewLambdaAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create Lambda auditor: %w", err)
	}

	deprecated, err := auditor.FindDeprecatedRuntimes(ctx)
	if err != nil {
		return fmt.Errorf("failed to find deprecated runtimes: %w", err)
	}

	publicURLs, err := auditor.FindPublicFunctionURLs(ctx)
	if err != nil {
		return fmt.Errorf("failed to find public function URLs: %w", err)
	}

	overprovisioned, err := auditor.FindOverprovisionedFunctions(ctx)
	if err != nil {
		return fmt.Errorf("failed to find over-provisioned functions: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderLambdaResults(deprecated, publicURLs, overprovisioned); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runSecurityIAM(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	fmt.Println("🔍 Analyzing IAM users, access keys, and roles...")
	fmt.Println()

	auditor, err := aws.NewIamAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create IAM auditor: %w", err)
	}

	noMFA, err := auditor.FindUsersWithoutMFA(ctx)
	if err != nil {
		return fmt.Errorf("failed to find users without MFA: %w", err)
	}

	oldKeys, err := auditor.FindOldAccessKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to find old access keys: %w", err)
	}

	overpermissioned, err := auditor.FindOverpermissionedRoles(ctx)
	if err != nil {
		return fmt.Errorf("failed to find over-permissioned roles: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderIAMResults(noMFA, oldKeys, overpermissioned); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runSecuritySecrets(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	fmt.Printf("🔍 Scanning SSM parameters and Lambda env vars for plaintext secrets in %s...\n\n", region)

	auditor, err := aws.NewSecretsAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create secrets auditor: %w", err)
	}

	ssmSecrets, err := auditor.FindPlaintextSSMSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to find plaintext SSM secrets: %w", err)
	}

	lambdaEnvVars, err := auditor.FindLambdaPlaintextEnvVars(ctx)
	if err != nil {
		return fmt.Errorf("failed to find Lambda plaintext env vars: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderSecretsResults(ssmSecrets, lambdaEnvVars); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runSecurityEKS(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	if secCluster == "" {
		fmt.Printf("🔍 Scanning EKS security in %s...\n\n", region)
	} else {
		fmt.Printf("🔍 Scanning EKS security for cluster %q (%s)...\n\n", secCluster, region)
	}

	auditor, err := eks.NewEKSSecurityAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create EKS security auditor: %w", err)
	}

	publicEndpoints, err := auditor.FindPublicEndpointClusters(ctx)
	if err != nil {
		return fmt.Errorf("failed to find public endpoint clusters: %w", err)
	}

	rootPods, err := auditor.FindPodsRunningAsRoot(ctx, secNamespace)
	if err != nil {
		return fmt.Errorf("failed to find pods running as root: %w", err)
	}

	outdated, err := auditor.FindOutdatedClusterVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to find outdated cluster versions: %w", err)
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderEKSSecurityResults(publicEndpoints, rootPods, outdated); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	return nil
}

func runSecurityRDS(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	fmt.Printf("🔍 Scanning RDS instances and snapshots in %s...\n\n", region)

	auditor, err := aws.NewRDSSecurityAuditor(ctx, region)
	if err != nil {
		return fmt.Errorf("failed to create RDS security auditor: %w", err)
	}

	findings, err := collectRDSSecurityFindings(ctx, auditor)
	if err != nil {
		return err
	}

	rep := reporter.NewReporter(outputFormat)
	if err := rep.RenderRDSSecurityResults(findings); err != nil {
		return fmt.Errorf("failed to render results: %w", err)
	}

	// Fail the pipeline if any critical findings were reported.
	if criticalCount := countCriticalRDS(findings); criticalCount > 0 {
		return fmt.Errorf("%d critical RDS security finding(s) detected", criticalCount)
	}

	return nil
}

// collectRDSSecurityFindings runs all nine RDS security checks and returns the
// combined findings.
func collectRDSSecurityFindings(ctx context.Context, auditor *aws.RDSSecurityAuditor) ([]aws.RDSSecurityFinding, error) {
	checks := []func(context.Context) ([]aws.RDSSecurityFinding, error){
		auditor.FindUnencryptedInstances,
		auditor.FindPubliclyAccessibleInstances,
		auditor.FindInstancesWithoutBackups,
		auditor.FindInstancesWithoutDeletionProtection,
		auditor.FindEOLEngineVersions,
		auditor.FindInsecureParameterGroups,
		auditor.FindInstancesWithoutMultiAZ,
		auditor.FindDefaultMasterUsernames,
		auditor.FindPublicSnapshots,
	}

	findings := make([]aws.RDSSecurityFinding, 0)
	for _, check := range checks {
		out, err := check(ctx)
		if err != nil {
			return nil, fmt.Errorf("RDS security check failed: %w", err)
		}
		findings = append(findings, out...)
	}

	return findings, nil
}

// countCriticalRDS returns the number of critical-severity RDS findings.
func countCriticalRDS(findings []aws.RDSSecurityFinding) int {
	count := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			count++
		}
	}
	return count
}

func runSecurityAudit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	region := resolveSecurityRegion()

	if secCluster == "" {
		fmt.Printf("🔍 Running full security audit in %s...\n\n", region)
	} else {
		fmt.Printf("🔍 Running full security audit for cluster %q (%s)...\n\n", secCluster, region)
	}

	rep := reporter.NewReporter(outputFormat)

	// IMDS
	if imdsAuditor, err := aws.NewIMDSAuditor(ctx, region); err != nil {
		warnSecurity("IMDS", err)
	} else if findings, err := imdsAuditor.FindInstancesWithIMDSv1(ctx); err != nil {
		warnSecurity("IMDS", err)
	} else if err := rep.RenderIMDSResults(findings); err != nil {
		return fmt.Errorf("failed to render IMDS results: %w", err)
	}

	// Lambda
	if lambdaAuditor, err := aws.NewLambdaAuditor(ctx, region); err != nil {
		warnSecurity("Lambda", err)
	} else {
		deprecated, e1 := lambdaAuditor.FindDeprecatedRuntimes(ctx)
		publicURLs, e2 := lambdaAuditor.FindPublicFunctionURLs(ctx)
		overprovisioned, e3 := lambdaAuditor.FindOverprovisionedFunctions(ctx)
		if err := firstErr(e1, e2, e3); err != nil {
			warnSecurity("Lambda", err)
		} else if err := rep.RenderLambdaResults(deprecated, publicURLs, overprovisioned); err != nil {
			return fmt.Errorf("failed to render Lambda results: %w", err)
		}
	}

	// IAM
	if iamAuditor, err := aws.NewIamAuditor(ctx, region); err != nil {
		warnSecurity("IAM", err)
	} else {
		noMFA, e1 := iamAuditor.FindUsersWithoutMFA(ctx)
		oldKeys, e2 := iamAuditor.FindOldAccessKeys(ctx)
		roles, e3 := iamAuditor.FindOverpermissionedRoles(ctx)
		if err := firstErr(e1, e2, e3); err != nil {
			warnSecurity("IAM", err)
		} else if err := rep.RenderIAMResults(noMFA, oldKeys, roles); err != nil {
			return fmt.Errorf("failed to render IAM results: %w", err)
		}
	}

	// Secrets
	if secretsAuditor, err := aws.NewSecretsAuditor(ctx, region); err != nil {
		warnSecurity("Secrets", err)
	} else {
		ssmSecrets, e1 := secretsAuditor.FindPlaintextSSMSecrets(ctx)
		lambdaEnvVars, e2 := secretsAuditor.FindLambdaPlaintextEnvVars(ctx)
		if err := firstErr(e1, e2); err != nil {
			warnSecurity("Secrets", err)
		} else if err := rep.RenderSecretsResults(ssmSecrets, lambdaEnvVars); err != nil {
			return fmt.Errorf("failed to render secrets results: %w", err)
		}
	}

	// EKS
	if eksAuditor, err := eks.NewEKSSecurityAuditor(ctx, region); err != nil {
		warnSecurity("EKS", err)
	} else {
		publicEndpoints, e1 := eksAuditor.FindPublicEndpointClusters(ctx)
		rootPods, e2 := eksAuditor.FindPodsRunningAsRoot(ctx, secNamespace)
		outdated, e3 := eksAuditor.FindOutdatedClusterVersions(ctx)
		if err := firstErr(e1, e2, e3); err != nil {
			warnSecurity("EKS", err)
		} else if err := rep.RenderEKSSecurityResults(publicEndpoints, rootPods, outdated); err != nil {
			return fmt.Errorf("failed to render EKS results: %w", err)
		}
	}

	// RDS
	if rdsAuditor, err := aws.NewRDSSecurityAuditor(ctx, region); err != nil {
		warnSecurity("RDS", err)
	} else if findings, err := collectRDSSecurityFindings(ctx, rdsAuditor); err != nil {
		warnSecurity("RDS", err)
	} else if err := rep.RenderRDSSecurityResults(findings); err != nil {
		return fmt.Errorf("failed to render RDS results: %w", err)
	}

	return nil
}

// warnSecurity prints a non-fatal warning so one failing domain does not abort
// the combined audit.
func warnSecurity(domain string, err error) {
	fmt.Printf("⚠️  Skipping %s checks: %v\n\n", domain, err)
}

// firstErr returns the first non-nil error, or nil.
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
