package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// secretPatterns are case-insensitive substrings that suggest a name refers to
// a secret. Matching is on names/keys only; values are never read or logged.
var secretPatterns = []string{
	"password", "passwd", "secret", "key", "token",
	"credential", "api_key", "apikey", "auth", "private",
}

// SecretsAuditor looks for secrets stored in plaintext across SSM Parameter
// Store and Lambda environment variables.
type SecretsAuditor struct {
	ssmClient    *ssm.Client
	lambdaClient *lambda.Client
	region       string
}

// SecretFinding describes a potential plaintext secret. It records only the
// resource and key names, never the underlying value.
type SecretFinding struct {
	ResourceType  string // "ssm_parameter" or "lambda_env_var"
	ResourceName  string // parameter name or function name
	SecretKeyName string // parameter name or env var key — never the value
	RiskNote      string
}

// NewSecretsAuditor creates a new SecretsAuditor for the given region.
func NewSecretsAuditor(ctx context.Context, region string) (*SecretsAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &SecretsAuditor{
		ssmClient:    ssm.NewFromConfig(cfg),
		lambdaClient: lambda.NewFromConfig(cfg),
		region:       region,
	}, nil
}

// FindPlaintextSSMSecrets flags SSM String parameters (not SecureString) whose
// names look like secrets.
func (a *SecretsAuditor) FindPlaintextSSMSecrets(ctx context.Context) ([]SecretFinding, error) {
	findings := make([]SecretFinding, 0)
	var nextToken *string

	for {
		out, err := a.ssmClient.DescribeParameters(ctx, &ssm.DescribeParametersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe SSM parameters: %w", err)
		}

		for _, param := range out.Parameters {
			// Only plaintext String parameters are at risk; SecureString is
			// encrypted with KMS.
			if param.Type != ssmtypes.ParameterTypeString {
				continue
			}

			name := aws.ToString(param.Name)
			if !looksLikeSecret(name) {
				continue
			}

			findings = append(findings, SecretFinding{
				ResourceType:  "ssm_parameter",
				ResourceName:  name,
				SecretKeyName: name,
				RiskNote:      "plaintext secret in SSM String parameter",
			})
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return findings, nil
}

// FindLambdaPlaintextEnvVars flags Lambda environment variable keys that look
// like secrets. Only key names are inspected and reported; values are never
// read.
func (a *SecretsAuditor) FindLambdaPlaintextEnvVars(ctx context.Context) ([]SecretFinding, error) {
	functions, err := a.listFunctionNames(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]SecretFinding, 0)
	for _, name := range functions {
		cfg, err := a.lambdaClient.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{
			FunctionName: aws.String(name),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get function configuration for %s: %w", name, err)
		}

		if cfg.Environment == nil {
			continue
		}

		for key := range cfg.Environment.Variables {
			if !looksLikeSecret(key) {
				continue
			}

			findings = append(findings, SecretFinding{
				ResourceType:  "lambda_env_var",
				ResourceName:  name,
				SecretKeyName: key,
				RiskNote:      "potential secret in Lambda environment variable (unencrypted at rest)",
			})
		}
	}

	return findings, nil
}

// listFunctionNames returns every Lambda function name in the region, following
// pagination via NextMarker.
func (a *SecretsAuditor) listFunctionNames(ctx context.Context) ([]string, error) {
	names := make([]string, 0)
	var marker *string

	for {
		out, err := a.lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("failed to list functions: %w", err)
		}

		for _, fn := range out.Functions {
			names = append(names, aws.ToString(fn.FunctionName))
		}

		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}

	return names, nil
}

// looksLikeSecret reports whether a parameter name or env var key matches any of
// the secret-name patterns (case-insensitive).
func looksLikeSecret(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range secretPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
