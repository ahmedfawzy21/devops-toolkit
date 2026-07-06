package aws

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestIMDSv1Allowed(t *testing.T) {
	tests := []struct {
		name       string
		httpTokens string
		want       bool
	}{
		{name: "required enforces IMDSv2", httpTokens: "required", want: false},
		{name: "optional allows IMDSv1", httpTokens: "optional", want: true},
		{name: "empty (nil in API) allows IMDSv1", httpTokens: "", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := imdsv1Allowed(tt.httpTokens); got != tt.want {
				t.Errorf("imdsv1Allowed(%q) = %v, want %v", tt.httpTokens, got, tt.want)
			}
		})
	}
}

func TestIMDSRemediation(t *testing.T) {
	got := imdsRemediation("i-0abc123", "us-east-1")
	want := "aws ec2 modify-instance-metadata-options --instance-id i-0abc123 --http-tokens required --region us-east-1"
	if got != want {
		t.Errorf("imdsRemediation() = %q, want %q", got, want)
	}
}

func TestIMDSv1RiskNoteContent(t *testing.T) {
	// The risk note should reference the credential-theft vector so the output
	// is actionable and educational.
	for _, want := range []string{"IMDSv1", "SSRF", "IAM credentials", "Capital One"} {
		if !strings.Contains(imdsv1RiskNote, want) {
			t.Errorf("imdsv1RiskNote missing %q; got %q", want, imdsv1RiskNote)
		}
	}
}

func TestInstanceNameTag(t *testing.T) {
	tags := []ec2types.Tag{
		{Key: aws.String("Environment"), Value: aws.String("prod")},
	}
	if got := instanceNameTag(tags); got != "" {
		t.Errorf("instanceNameTag with no Name tag = %q, want empty", got)
	}

	tags = append(tags, ec2types.Tag{Key: aws.String("Name"), Value: aws.String("web-server")})
	if got := instanceNameTag(tags); got != "web-server" {
		t.Errorf("instanceNameTag = %q, want %q", got, "web-server")
	}
}
