package aws

import (
	"testing"
	"time"
)

// sampleCredentialReport mirrors the real IAM credential-report CSV layout
// (header order matters less than column names, which the parser keys on).
const sampleCredentialReport = `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated
<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,2024-01-01T00:00:00+00:00,not_supported,not_supported,false,false,N/A
alice,arn:aws:iam::123456789012:user/alice,2021-05-01T00:00:00+00:00,true,2024-06-01T00:00:00+00:00,2021-05-01T00:00:00+00:00,N/A,false,true,2021-05-01T00:00:00+00:00
bob,arn:aws:iam::123456789012:user/bob,2021-05-01T00:00:00+00:00,true,2024-06-01T00:00:00+00:00,2021-05-01T00:00:00+00:00,N/A,true,true,2021-05-01T00:00:00+00:00
carol,arn:aws:iam::123456789012:user/carol,2021-05-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2021-05-01T00:00:00+00:00
`

func TestParseCredentialReportForMFA(t *testing.T) {
	findings, err := parseCredentialReportForMFA([]byte(sampleCredentialReport))
	if err != nil {
		t.Fatalf("parseCredentialReportForMFA returned error: %v", err)
	}

	// Only alice: console password enabled AND no MFA. bob has MFA, carol has no
	// console password, root is not_supported.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.ResourceName != "alice" {
		t.Errorf("ResourceName = %q, want alice", f.ResourceName)
	}
	if f.Issue != "no_mfa" {
		t.Errorf("Issue = %q, want no_mfa", f.Issue)
	}
	if f.ResourceType != "user" {
		t.Errorf("ResourceType = %q, want user", f.ResourceType)
	}
}

func TestParseCredentialReportForMFA_HeaderOnly(t *testing.T) {
	findings, err := parseCredentialReportForMFA([]byte("user,password_enabled,mfa_active\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestParseCredentialReportForMFA_MissingColumns(t *testing.T) {
	if _, err := parseCredentialReportForMFA([]byte("user,arn\nalice,arn:x\n")); err == nil {
		t.Error("expected error for missing columns, got nil")
	}
}

func TestAccessKeyAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		created time.Time
		want    int
	}{
		{name: "100 days old", created: now.AddDate(0, 0, -100), want: 100},
		{name: "same day", created: now, want: 0},
		{name: "one day", created: now.Add(-25 * time.Hour), want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accessKeyAgeDays(tt.created, now); got != tt.want {
				t.Errorf("accessKeyAgeDays = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIsOldAccessKey(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		ageDays int
		want    bool
	}{
		{name: "active and 91 days -> old", status: "Active", ageDays: 91, want: true},
		{name: "active and exactly 90 -> not old", status: "Active", ageDays: 90, want: false},
		{name: "inactive old key -> ignored", status: "Inactive", ageDays: 500, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOldAccessKey(tt.status, tt.ageDays); got != tt.want {
				t.Errorf("isOldAccessKey(%q, %d) = %v, want %v", tt.status, tt.ageDays, got, tt.want)
			}
		})
	}
}

func TestPolicyGrantsAdmin(t *testing.T) {
	// URL-encoded admin document: Effect Allow, Action *, Resource *.
	adminDoc := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D`
	doc, err := parsePolicyDocument(adminDoc)
	if err != nil {
		t.Fatalf("parsePolicyDocument returned error: %v", err)
	}
	if !policyGrantsAdmin(doc) {
		t.Error("expected admin document to be flagged")
	}

	// Scoped document: Allow s3:GetObject on a specific bucket.
	scoped := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::my-bucket/*"]}]}`
	scopedDoc, err := parsePolicyDocument(scoped)
	if err != nil {
		t.Fatalf("parsePolicyDocument returned error: %v", err)
	}
	if policyGrantsAdmin(scopedDoc) {
		t.Error("scoped document should not be flagged as admin")
	}
}
