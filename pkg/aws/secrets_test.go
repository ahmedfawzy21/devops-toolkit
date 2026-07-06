package aws

import "testing"

func TestLooksLikeSecret(t *testing.T) {
	matching := []string{
		"DB_PASSWORD",
		"passwd",
		"api_key",
		"APIKEY",
		"MY_SECRET",
		"github_token",
		"AWS_CREDENTIAL",
		"authToken",
		"private_key",
		"/prod/service/DatabasePassword",
		"STRIPE_API_KEY",
	}
	for _, name := range matching {
		if !looksLikeSecret(name) {
			t.Errorf("looksLikeSecret(%q) = false, want true", name)
		}
	}

	nonMatching := []string{
		"LOG_LEVEL",
		"REGION",
		"timeout_seconds",
		"MAX_CONNECTIONS",
		"feature_flag_enabled",
		"hostname",
	}
	for _, name := range nonMatching {
		if looksLikeSecret(name) {
			t.Errorf("looksLikeSecret(%q) = true, want false", name)
		}
	}
}

func TestSecretPatternsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"PASSWORD", "Password", "password", "PaSsWoRd"} {
		if !looksLikeSecret(name) {
			t.Errorf("looksLikeSecret(%q) should be case-insensitive", name)
		}
	}
}
