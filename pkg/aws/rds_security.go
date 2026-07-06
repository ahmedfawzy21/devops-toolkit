package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// RDSSecurityAuditor inspects RDS instances and snapshots for MySQL/PostgreSQL
// security-posture issues. It reuses the same *rds.Client for instance,
// parameter-group, and snapshot inspection.
type RDSSecurityAuditor struct {
	rdsClient *rds.Client
	region    string
}

// RDSSecurityFinding describes a single RDS security issue.
type RDSSecurityFinding struct {
	DBInstanceIdentifier string
	Engine               string // "mysql", "postgres", "aurora-mysql", etc.
	EngineVersion        string
	DBInstanceClass      string
	Issue                string // snake_case identifier
	Severity             string // "critical", "warning"
	RiskNote             string
	Remediation          string // short AWS CLI or console action
}

// insecureParamTimeout bounds the DescribeDBParameters calls for a single
// instance so one slow parameter group cannot stall the whole scan.
const insecureParamTimeout = 30 * time.Second

// eolInfo pairs an engine version's EOL severity with its (approximate) EOL date.
type eolInfo struct {
	severity string
	date     string
}

// mysqlEOL and postgresEOL map an engine major-version prefix to its EOL status.
// These dates are approximate — actual EOL dates should be verified at
// https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/MySQL.Concepts.VersionMgmt.html
var mysqlEOL = map[string]eolInfo{
	"5.7": {severity: "critical", date: "October 2023"},
	"8.0": {severity: "warning", date: "April 2026"},
}

var postgresEOL = map[string]eolInfo{
	"11": {severity: "critical", date: "November 2023"},
	"12": {severity: "critical", date: "November 2024"},
	"13": {severity: "critical", date: "November 2025"},
	"14": {severity: "warning", date: "November 2026"},
}

// devInstanceClasses are small dev/test instance classes that are exempt from the
// Multi-AZ production check.
var devInstanceClasses = map[string]bool{
	"db.t3.micro": true,
	"db.t3.small": true,
	"db.t2.micro": true,
	"db.t2.small": true,
}

// defaultMasterUsernames are predictable master usernames that make credential
// guessing easier.
var defaultMasterUsernames = map[string]bool{
	"admin":         true,
	"root":          true,
	"postgres":      true,
	"mysql":         true,
	"administrator": true,
	"sa":            true,
	"rdsadmin":      true,
}

// NewRDSSecurityAuditor creates a new RDSSecurityAuditor for the given region.
func NewRDSSecurityAuditor(ctx context.Context, region string) (*RDSSecurityAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &RDSSecurityAuditor{
		rdsClient: rds.NewFromConfig(cfg),
		region:    region,
	}, nil
}

// listInstances returns every DB instance in the region, following pagination
// via Marker.
func (a *RDSSecurityAuditor) listInstances(ctx context.Context) ([]rdstypes.DBInstance, error) {
	instances := make([]rdstypes.DBInstance, 0)
	var marker *string

	for {
		out, err := a.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
		}

		instances = append(instances, out.DBInstances...)

		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return instances, nil
}

// findingFor seeds an RDSSecurityFinding with the identifying fields common to
// every instance-level finding.
func findingFor(inst rdstypes.DBInstance) RDSSecurityFinding {
	return RDSSecurityFinding{
		DBInstanceIdentifier: aws.ToString(inst.DBInstanceIdentifier),
		Engine:               aws.ToString(inst.Engine),
		EngineVersion:        aws.ToString(inst.EngineVersion),
		DBInstanceClass:      aws.ToString(inst.DBInstanceClass),
	}
}

// FindUnencryptedInstances flags instances whose storage is not encrypted at rest.
func (a *RDSSecurityAuditor) FindUnencryptedInstances(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		if aws.ToBool(inst.StorageEncrypted) {
			continue
		}
		f := findingFor(inst)
		f.Issue = "not_encrypted_at_rest"
		f.Severity = "critical"
		f.RiskNote = "storage not encrypted at rest; underlying EBS volumes readable if detached or snapshotted without authorization"
		f.Remediation = "encryption cannot be enabled on a running instance; snapshot → restore with encryption enabled → promote"
		findings = append(findings, f)
	}

	return findings, nil
}

// FindPubliclyAccessibleInstances flags instances whose endpoint is resolvable
// from the public internet.
func (a *RDSSecurityAuditor) FindPubliclyAccessibleInstances(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		if !aws.ToBool(inst.PubliclyAccessible) {
			continue
		}
		f := findingFor(inst)
		f.Issue = "publicly_accessible"
		f.Severity = "critical"
		f.RiskNote = "DB endpoint resolvable from the public internet; attack surface includes brute-force, credential stuffing, and any unpatched engine CVEs"
		f.Remediation = "modify-db-instance --no-publicly-accessible (requires brief maintenance window)"
		findings = append(findings, f)
	}

	return findings, nil
}

// FindInstancesWithoutBackups flags instances with automated backups disabled.
func (a *RDSSecurityAuditor) FindInstancesWithoutBackups(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		if aws.ToInt32(inst.BackupRetentionPeriod) != 0 {
			continue
		}
		f := findingFor(inst)
		f.Issue = "no_automated_backups"
		f.Severity = "critical"
		f.RiskNote = "automated backups disabled; no point-in-time recovery available — data loss is permanent on accidental delete or corruption"
		f.Remediation = "modify-db-instance --backup-retention-period 7"
		findings = append(findings, f)
	}

	return findings, nil
}

// FindInstancesWithoutDeletionProtection flags instances that can be deleted
// without a confirmation step.
func (a *RDSSecurityAuditor) FindInstancesWithoutDeletionProtection(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		if aws.ToBool(inst.DeletionProtection) {
			continue
		}
		f := findingFor(inst)
		f.Issue = "no_deletion_protection"
		f.Severity = "warning"
		f.RiskNote = "instance can be permanently deleted with a single API call or console click; no confirmation required"
		f.Remediation = "modify-db-instance --deletion-protection"
		findings = append(findings, f)
	}

	return findings, nil
}

// FindEOLEngineVersions flags instances running end-of-life or near-EOL engine
// versions.
func (a *RDSSecurityAuditor) FindEOLEngineVersions(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		engine := aws.ToString(inst.Engine)
		version := aws.ToString(inst.EngineVersion)

		info, flagged := checkEOLVersion(engine, version)
		if !flagged {
			continue
		}

		f := findingFor(inst)
		f.Issue = "eol_engine_version"
		f.Severity = info.severity
		f.RiskNote = fmt.Sprintf("engine version %s reached end of life on %s; no security patches from AWS after EOL — known CVEs will not be fixed", version, info.date)
		f.Remediation = "modify-db-instance --engine-version <latest> (test in staging first; major version upgrades require compatibility validation)"
		findings = append(findings, f)
	}

	return findings, nil
}

// checkEOLVersion reports whether an engine version is EOL/near-EOL and, if so,
// its severity and EOL date. Matching is by major-version prefix so that e.g.
// "5.7.44" and the Aurora string "5.7.mysql_aurora.2.11.0" both match "5.7". It
// is pure so it can be tested without an AWS client.
func checkEOLVersion(engine, engineVersion string) (eolInfo, bool) {
	var m map[string]eolInfo
	switch engine {
	case "mysql", "aurora-mysql":
		m = mysqlEOL
	case "postgres", "aurora-postgresql":
		m = postgresEOL
	default:
		return eolInfo{}, false
	}

	for prefix, info := range m {
		if engineVersion == prefix || strings.HasPrefix(engineVersion, prefix+".") {
			return info, true
		}
	}
	return eolInfo{}, false
}

// paramIssue is an insecure-parameter finding decoupled from any specific
// instance, so the matching logic can be unit-tested in isolation.
type paramIssue struct {
	Issue       string
	Severity    string
	RiskNote    string
	Remediation string
}

// insecureParamNames lists the parameter names FindInsecureParameterGroups needs
// to inspect, so we can capture only these values instead of loading every
// parameter into memory.
var insecureParamNames = map[string]bool{
	"local_infile":    true,
	"general_log":     true,
	"log_output":      true,
	"ssl":             true,
	"log_connections": true,
}

// FindInsecureParameterGroups inspects each instance's primary parameter group
// for known-insecure settings. A failure for one instance (e.g. a custom
// parameter group that cannot be read) logs a warning and continues.
func (a *RDSSecurityAuditor) FindInsecureParameterGroups(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		if len(inst.DBParameterGroups) == 0 {
			continue
		}
		groupName := aws.ToString(inst.DBParameterGroups[0].DBParameterGroupName)
		if groupName == "" {
			continue
		}

		params, err := a.relevantParameters(ctx, groupName)
		if err != nil {
			fmt.Printf("Warning: failed to read parameter group %s for %s: %v\n", groupName, aws.ToString(inst.DBInstanceIdentifier), err)
			continue
		}

		for _, issue := range evaluateInsecureParameters(aws.ToString(inst.Engine), params) {
			f := findingFor(inst)
			f.Issue = issue.Issue
			f.Severity = issue.Severity
			f.RiskNote = issue.RiskNote
			f.Remediation = issue.Remediation
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// relevantParameters pages through a parameter group and returns only the values
// of the parameters we care about, keeping memory bounded regardless of how many
// hundreds of parameters the group defines. A 30s timeout bounds slow groups.
func (a *RDSSecurityAuditor) relevantParameters(ctx context.Context, groupName string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, insecureParamTimeout)
	defer cancel()

	values := make(map[string]string)
	var marker *string

	for {
		out, err := a.rdsClient.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
			DBParameterGroupName: aws.String(groupName),
			Marker:               marker,
		})
		if err != nil {
			return nil, err
		}

		for _, p := range out.Parameters {
			name := aws.ToString(p.ParameterName)
			if !insecureParamNames[name] {
				continue
			}
			if p.ParameterValue != nil {
				values[name] = aws.ToString(p.ParameterValue)
			}
		}

		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return values, nil
}

// evaluateInsecureParameters applies the insecure-parameter rules to the
// captured parameter values for a given engine. It is pure string comparison so
// it can be unit-tested without an AWS client.
func evaluateInsecureParameters(engine string, params map[string]string) []paramIssue {
	issues := make([]paramIssue, 0)

	switch engine {
	case "mysql", "aurora-mysql":
		if params["local_infile"] == "1" {
			issues = append(issues, paramIssue{
				Issue:       "mysql_local_infile_enabled",
				Severity:    "critical",
				RiskNote:    "LOCAL INFILE allows the DB server to read arbitrary files from the filesystem; exploitable via SQL injection to exfiltrate /etc/passwd, credentials, etc",
				Remediation: "set local_infile=0 in the parameter group (requires DB restart if static parameter)",
			})
		}
		if params["general_log"] == "1" && strings.Contains(strings.ToUpper(params["log_output"]), "FILE") {
			issues = append(issues, paramIssue{
				Issue:       "mysql_general_log_to_file",
				Severity:    "warning",
				RiskNote:    "general query log writes every SQL statement to disk including plaintext passwords in INSERT/UPDATE statements; log files may be accessible to OS users",
				Remediation: "set general_log=0 or log_output=TABLE to keep logs in memory only",
			})
		}
	case "postgres", "aurora-postgresql":
		if v, ok := params["ssl"]; ok && v == "0" {
			issues = append(issues, paramIssue{
				Issue:       "postgres_ssl_disabled",
				Severity:    "critical",
				RiskNote:    "SSL/TLS disabled for all PostgreSQL connections; credentials and query results transmitted in plaintext",
				Remediation: "set ssl=1 in parameter group (RDS default)",
			})
		}
		if v, ok := params["log_connections"]; ok && v == "0" {
			issues = append(issues, paramIssue{
				Issue:       "postgres_log_connections_disabled",
				Severity:    "warning",
				RiskNote:    "connection logging disabled; no audit trail of who connected to the database and when",
				Remediation: "set log_connections=1 in parameter group",
			})
		}
	}

	return issues
}

// FindInstancesWithoutMultiAZ flags production-sized instances deployed in a
// single AZ. Small dev/test classes are skipped.
func (a *RDSSecurityAuditor) FindInstancesWithoutMultiAZ(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		if aws.ToBool(inst.MultiAZ) {
			continue
		}
		if isDevInstanceClass(aws.ToString(inst.DBInstanceClass)) {
			continue
		}
		f := findingFor(inst)
		f.Issue = "no_multi_az"
		f.Severity = "warning"
		f.RiskNote = "single-AZ deployment; AZ failure causes downtime until AWS detects failure and restores (typically 1-2 minutes but can be longer)"
		f.Remediation = "modify-db-instance --multi-az (triggers a brief failover during the next maintenance window)"
		findings = append(findings, f)
	}

	return findings, nil
}

// isDevInstanceClass reports whether a class is a small dev/test tier exempt from
// the Multi-AZ production check.
func isDevInstanceClass(class string) bool {
	return devInstanceClasses[class]
}

// FindDefaultMasterUsernames flags instances using a default or predictable
// master username.
func (a *RDSSecurityAuditor) FindDefaultMasterUsernames(ctx context.Context) ([]RDSSecurityFinding, error) {
	instances, err := a.listInstances(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, inst := range instances {
		username := aws.ToString(inst.MasterUsername)
		if !isDefaultMasterUsername(username) {
			continue
		}
		f := findingFor(inst)
		f.Issue = "default_master_username"
		f.Severity = "warning"
		f.RiskNote = "default or predictable master username makes credential guessing trivially easier in combination with any other exposure (public accessibility, weak password)"
		f.Remediation = "cannot change master username after creation; create a named application user and restrict master account usage to break-glass scenarios only"
		findings = append(findings, f)
	}

	return findings, nil
}

// isDefaultMasterUsername reports whether a master username is one of the known
// default/predictable names.
func isDefaultMasterUsername(username string) bool {
	return defaultMasterUsernames[strings.ToLower(username)]
}

// FindPublicSnapshots flags manual DB snapshots that are restorable by any AWS
// account. RDS DescribeDBSnapshots has no OwnerIds field (that is EC2
// terminology); self-owned snapshots are retrieved with SnapshotType "manual",
// and only manual snapshots can be shared/made public in the first place.
func (a *RDSSecurityAuditor) FindPublicSnapshots(ctx context.Context) ([]RDSSecurityFinding, error) {
	snapshots := make([]rdstypes.DBSnapshot, 0)
	var marker *string
	for {
		out, err := a.rdsClient.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{
			SnapshotType: aws.String("manual"),
			Marker:       marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DB snapshots: %w", err)
		}

		snapshots = append(snapshots, out.DBSnapshots...)

		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	findings := make([]RDSSecurityFinding, 0)
	for _, snap := range snapshots {
		snapshotID := aws.ToString(snap.DBSnapshotIdentifier)

		attrOut, err := a.rdsClient.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
			DBSnapshotIdentifier: snap.DBSnapshotIdentifier,
		})
		if err != nil {
			fmt.Printf("Warning: failed to read snapshot attributes for %s: %v\n", snapshotID, err)
			continue
		}
		if attrOut.DBSnapshotAttributesResult == nil {
			continue
		}

		if !snapshotIsPublic(attrOut.DBSnapshotAttributesResult.DBSnapshotAttributes) {
			continue
		}

		findings = append(findings, RDSSecurityFinding{
			DBInstanceIdentifier: snapshotID,
			Engine:               aws.ToString(snap.Engine),
			EngineVersion:        aws.ToString(snap.EngineVersion),
			// DBSnapshot carries no instance class; leave it blank.
			Issue:       "public_snapshot",
			Severity:    "critical",
			RiskNote:    "snapshot is publicly restorable by ANY AWS account; anyone can restore a full copy of your database including all data",
			Remediation: "modify-db-snapshot-attribute --attribute-name restore --values-to-remove all",
		})
	}

	return findings, nil
}

// snapshotIsPublic reports whether the "restore" attribute grants access to
// "all" (every AWS account).
func snapshotIsPublic(attrs []rdstypes.DBSnapshotAttribute) bool {
	for _, attr := range attrs {
		if aws.ToString(attr.AttributeName) != "restore" {
			continue
		}
		for _, v := range attr.AttributeValues {
			if v == "all" {
				return true
			}
		}
	}
	return false
}
