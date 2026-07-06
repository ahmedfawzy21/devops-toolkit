package aws

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// accessKeyMaxAgeDays is the rotation threshold above which an active access key
// is flagged.
const accessKeyMaxAgeDays = 90

// roleStaleDays is the number of days without use above which a broadly
// permissioned role is treated as an unused (and therefore riskier) role.
const roleStaleDays = 90

// IamAuditor performs deep IAM analysis. IAM is a global service; the region is
// retained only for constructor consistency with the other auditors.
type IamAuditor struct {
	iamClient *iam.Client
	region    string
}

// IAMFinding describes a single IAM security issue.
type IAMFinding struct {
	ResourceType     string // "user", "role", or "key"
	ResourceName     string
	Issue            string // "no_mfa", "old_access_key", "admin_policy", "unused_broad_role"
	DaysSinceLastUse int    // -1 when never used / not applicable
	PolicyName       string // the offending policy, when any
	RiskNote         string
}

// NewIamAuditor creates a new IamAuditor. IAM calls succeed from any region, so
// the region is only recorded for consistency with the other constructors.
func NewIamAuditor(ctx context.Context, region string) (*IamAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &IamAuditor{
		iamClient: iam.NewFromConfig(cfg),
		region:    region,
	}, nil
}

// FindUsersWithoutMFA flags console-enabled users that do not have MFA active,
// parsing the account credential report.
func (a *IamAuditor) FindUsersWithoutMFA(ctx context.Context) ([]IAMFinding, error) {
	report, err := a.fetchCredentialReport(ctx)
	if err != nil {
		return nil, err
	}
	return parseCredentialReportForMFA(report)
}

// FindOldAccessKeys flags active access keys older than the rotation threshold.
func (a *IamAuditor) FindOldAccessKeys(ctx context.Context) ([]IAMFinding, error) {
	users, err := a.listUsers(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	findings := make([]IAMFinding, 0)
	for _, user := range users {
		userName := aws.ToString(user.UserName)

		out, err := a.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list access keys for %s: %w", userName, err)
		}

		for _, key := range out.AccessKeyMetadata {
			ageDays := accessKeyAgeDays(aws.ToTime(key.CreateDate), now)
			if !isOldAccessKey(string(key.Status), ageDays) {
				continue
			}

			findings = append(findings, IAMFinding{
				ResourceType:     "key",
				ResourceName:     fmt.Sprintf("%s/%s", userName, aws.ToString(key.AccessKeyId)),
				Issue:            "old_access_key",
				DaysSinceLastUse: ageDays,
				RiskNote:         fmt.Sprintf("active access key is %d days old (> %d); rotate it to limit exposure from leaked credentials", ageDays, accessKeyMaxAgeDays),
			})
		}
	}

	return findings, nil
}

// FindOverpermissionedRoles flags roles with admin-equivalent permissions
// (AdministratorAccess or Action:* Resource:* Allow), noting those that also
// appear unused.
func (a *IamAuditor) FindOverpermissionedRoles(ctx context.Context) ([]IAMFinding, error) {
	roles, err := a.listRoles(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]IAMFinding, 0)
	for _, role := range roles {
		roleName := aws.ToString(role.RoleName)

		attached, err := a.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list attached policies for role %s: %w", roleName, err)
		}

		offendingPolicy, isBroad, err := a.attachedPoliciesGrantAdmin(ctx, attached.AttachedPolicies)
		if err != nil {
			return nil, err
		}
		if !isBroad {
			continue
		}

		daysSince, used, err := a.roleLastUsedDays(ctx, roleName)
		if err != nil {
			return nil, err
		}

		if !used || daysSince > roleStaleDays {
			note := fmt.Sprintf("role grants admin-equivalent access via %s and has not been used", offendingPolicy)
			if used {
				note = fmt.Sprintf("role grants admin-equivalent access via %s and was last used %d days ago", offendingPolicy, daysSince)
			}
			findings = append(findings, IAMFinding{
				ResourceType:     "role",
				ResourceName:     roleName,
				Issue:            "unused_broad_role",
				DaysSinceLastUse: daysSince,
				PolicyName:       offendingPolicy,
				RiskNote:         note,
			})
			continue
		}

		findings = append(findings, IAMFinding{
			ResourceType:     "role",
			ResourceName:     roleName,
			Issue:            "admin_policy",
			DaysSinceLastUse: daysSince,
			PolicyName:       offendingPolicy,
			RiskNote:         fmt.Sprintf("role grants admin-equivalent access via %s (Action:* Resource:* Allow)", offendingPolicy),
		})
	}

	return findings, nil
}

// fetchCredentialReport kicks off generation of the account credential report
// and polls until it is available, returning the raw CSV content.
func (a *IamAuditor) fetchCredentialReport(ctx context.Context) ([]byte, error) {
	if _, err := a.iamClient.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		return nil, fmt.Errorf("failed to generate credential report: %w", err)
	}

	for attempt := 0; attempt < 10; attempt++ {
		out, err := a.iamClient.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			return out.Content, nil
		}
		if !isReportNotReady(err) {
			return nil, fmt.Errorf("failed to get credential report: %w", err)
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("credential report was not ready after polling")
}

// isReportNotReady reports whether err indicates the credential report is still
// being generated (as opposed to a genuine failure).
func isReportNotReady(err error) bool {
	var notPresent *iamtypes.CredentialReportNotPresentException
	var notReady *iamtypes.CredentialReportNotReadyException
	return errors.As(err, &notPresent) || errors.As(err, &notReady)
}

// listUsers returns every IAM user, following pagination.
func (a *IamAuditor) listUsers(ctx context.Context) ([]iamtypes.User, error) {
	users := make([]iamtypes.User, 0)
	var marker *string

	for {
		out, err := a.iamClient.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}

		users = append(users, out.Users...)

		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return users, nil
}

// listRoles returns every IAM role, following pagination.
func (a *IamAuditor) listRoles(ctx context.Context) ([]iamtypes.Role, error) {
	roles := make([]iamtypes.Role, 0)
	var marker *string

	for {
		out, err := a.iamClient.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}

		roles = append(roles, out.Roles...)

		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return roles, nil
}

// attachedPoliciesGrantAdmin reports whether any attached policy grants
// admin-equivalent access, returning the offending policy's name. It treats the
// AWS managed AdministratorAccess policy as admin without fetching its document,
// and otherwise inspects each policy's default version.
func (a *IamAuditor) attachedPoliciesGrantAdmin(ctx context.Context, policies []iamtypes.AttachedPolicy) (string, bool, error) {
	for _, policy := range policies {
		name := aws.ToString(policy.PolicyName)
		if name == "AdministratorAccess" {
			return name, true, nil
		}

		doc, err := a.policyDefaultDocument(ctx, aws.ToString(policy.PolicyArn))
		if err != nil {
			return "", false, err
		}
		if policyGrantsAdmin(doc) {
			return name, true, nil
		}
	}

	return "", false, nil
}

// policyDefaultDocument fetches and decodes the default version document of a
// managed policy.
func (a *IamAuditor) policyDefaultDocument(ctx context.Context, policyArn string) (iamPolicyDocument, error) {
	getOut, err := a.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyArn)})
	if err != nil {
		return iamPolicyDocument{}, fmt.Errorf("failed to get policy %s: %w", policyArn, err)
	}
	if getOut.Policy == nil || getOut.Policy.DefaultVersionId == nil {
		return iamPolicyDocument{}, nil
	}

	versionOut, err := a.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: getOut.Policy.DefaultVersionId,
	})
	if err != nil {
		return iamPolicyDocument{}, fmt.Errorf("failed to get policy version for %s: %w", policyArn, err)
	}
	if versionOut.PolicyVersion == nil || versionOut.PolicyVersion.Document == nil {
		return iamPolicyDocument{}, nil
	}

	return parsePolicyDocument(aws.ToString(versionOut.PolicyVersion.Document))
}

// roleLastUsedDays returns the number of days since a role was last used and
// whether it has ever been used, sourced from the authoritative GetRole
// RoleLastUsed field.
func (a *IamAuditor) roleLastUsedDays(ctx context.Context, roleName string) (int, bool, error) {
	out, err := a.iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err != nil {
		return -1, false, fmt.Errorf("failed to get role %s: %w", roleName, err)
	}

	if out.Role == nil || out.Role.RoleLastUsed == nil || out.Role.RoleLastUsed.LastUsedDate == nil {
		return -1, false, nil
	}

	days := int(time.Since(aws.ToTime(out.Role.RoleLastUsed.LastUsedDate)).Hours() / 24)
	return days, true, nil
}

// parseCredentialReportForMFA parses the credential-report CSV and returns a
// finding for every console-enabled user without MFA. It is pure string
// processing so it can be tested without an AWS client.
func parseCredentialReportForMFA(csvData []byte) ([]IAMFinding, error) {
	reader := csv.NewReader(bytes.NewReader(csvData))

	header, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return make([]IAMFinding, 0), nil
		}
		return nil, fmt.Errorf("failed to read credential report header: %w", err)
	}

	index := make(map[string]int, len(header))
	for i, col := range header {
		index[col] = i
	}

	userIdx, ok1 := index["user"]
	pwdIdx, ok2 := index["password_enabled"]
	mfaIdx, ok3 := index["mfa_active"]
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("credential report missing expected columns (user, password_enabled, mfa_active)")
	}

	findings := make([]IAMFinding, 0)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read credential report row: %w", err)
		}

		if row[pwdIdx] == "true" && row[mfaIdx] == "false" {
			findings = append(findings, IAMFinding{
				ResourceType:     "user",
				ResourceName:     row[userIdx],
				Issue:            "no_mfa",
				DaysSinceLastUse: -1,
				RiskNote:         "console password enabled but MFA is not active; the account is one leaked password away from compromise",
			})
		}
	}

	return findings, nil
}

// accessKeyAgeDays returns the whole-day age of an access key at the given
// reference time.
func accessKeyAgeDays(createDate, now time.Time) int {
	return int(now.Sub(createDate).Hours() / 24)
}

// isOldAccessKey reports whether an access key is active and past the rotation
// threshold.
func isOldAccessKey(status string, ageDays int) bool {
	return status == string(iamtypes.StatusTypeActive) && ageDays > accessKeyMaxAgeDays
}

// iamPolicyDocument is a minimal view of an IAM policy document sufficient to
// detect admin-equivalent grants.
type iamPolicyDocument struct {
	Statement []iamPolicyStatement `json:"Statement"`
}

type iamPolicyStatement struct {
	Effect   string         `json:"Effect"`
	Action   flexStringList `json:"Action"`
	Resource flexStringList `json:"Resource"`
}

// flexStringList unmarshals a JSON field that may be either a single string or
// an array of strings (IAM allows both for Action and Resource).
type flexStringList []string

func (f *flexStringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*f = []string{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*f = many
	return nil
}

// parsePolicyDocument URL-decodes and unmarshals an IAM policy document. The
// Statement block may itself be a single object or an array; a leading decode
// handles the URL-encoding applied by GetPolicyVersion.
func parsePolicyDocument(encoded string) (iamPolicyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		// Some documents come back already decoded; fall back to the raw string.
		decoded = encoded
	}

	// Handle both the array and single-object forms of Statement by decoding
	// into a permissive structure first.
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &raw); err != nil {
		return iamPolicyDocument{}, fmt.Errorf("failed to parse policy document: %w", err)
	}

	doc := iamPolicyDocument{}
	if len(raw.Statement) == 0 {
		return doc, nil
	}

	if err := json.Unmarshal(raw.Statement, &doc.Statement); err != nil {
		// Single statement object rather than an array.
		var single iamPolicyStatement
		if err2 := json.Unmarshal(raw.Statement, &single); err2 != nil {
			return iamPolicyDocument{}, fmt.Errorf("failed to parse policy statements: %w", err)
		}
		doc.Statement = []iamPolicyStatement{single}
	}

	return doc, nil
}

// policyGrantsAdmin reports whether the document contains an Allow statement with
// Action:* and Resource:* (i.e. admin-equivalent access).
func policyGrantsAdmin(doc iamPolicyDocument) bool {
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if containsStar(stmt.Action) && containsStar(stmt.Resource) {
			return true
		}
	}
	return false
}

// containsStar reports whether the list contains the "*" wildcard.
func containsStar(values []string) bool {
	for _, v := range values {
		if v == "*" {
			return true
		}
	}
	return false
}
