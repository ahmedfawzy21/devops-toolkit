package k8s

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGetCertificateStatus(t *testing.T) {
	tests := []struct {
		name           string
		daysRemaining  int
		expectedStatus string
	}{
		{
			name:           "Expired certificate",
			daysRemaining:  -1,
			expectedStatus: "expired",
		},
		{
			name:           "Expired 10 days ago",
			daysRemaining:  -10,
			expectedStatus: "expired",
		},
		{
			name:           "Critical - 1 day remaining",
			daysRemaining:  1,
			expectedStatus: "critical",
		},
		{
			name:           "Critical - 6 days remaining",
			daysRemaining:  6,
			expectedStatus: "critical",
		},
		{
			name:           "Expiring soon - 7 days",
			daysRemaining:  7,
			expectedStatus: "expiring-soon",
		},
		{
			name:           "Expiring soon - 15 days",
			daysRemaining:  15,
			expectedStatus: "expiring-soon",
		},
		{
			name:           "Expiring soon - 29 days",
			daysRemaining:  29,
			expectedStatus: "expiring-soon",
		},
		{
			name:           "Valid - 30 days",
			daysRemaining:  30,
			expectedStatus: "valid",
		},
		{
			name:           "Valid - 60 days",
			daysRemaining:  60,
			expectedStatus: "valid",
		},
		{
			name:           "Valid - 365 days",
			daysRemaining:  365,
			expectedStatus: "valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := getCertificateStatus(tt.daysRemaining)
			if status != tt.expectedStatus {
				t.Errorf("getCertificateStatus(%d) = %q, expected %q",
					tt.daysRemaining, status, tt.expectedStatus)
			}
		})
	}
}

func TestFormatDNSNames(t *testing.T) {
	tests := []struct {
		name     string
		certInfo CertificateInfo
		expected string
	}{
		{
			name: "No DNS names",
			certInfo: CertificateInfo{
				DNSNames: []string{},
			},
			expected: "<none>",
		},
		{
			name: "Single DNS name",
			certInfo: CertificateInfo{
				DNSNames: []string{"example.com"},
			},
			expected: "example.com",
		},
		{
			name: "Two DNS names",
			certInfo: CertificateInfo{
				DNSNames: []string{"example.com", "www.example.com"},
			},
			expected: "example.com, www.example.com",
		},
		{
			name: "Three DNS names",
			certInfo: CertificateInfo{
				DNSNames: []string{"example.com", "www.example.com", "api.example.com"},
			},
			expected: "example.com, www.example.com, api.example.com",
		},
		{
			name: "More than three DNS names",
			certInfo: CertificateInfo{
				DNSNames: []string{"example.com", "www.example.com", "api.example.com", "app.example.com", "cdn.example.com"},
			},
			expected: "example.com, www.example.com, api.example.com (+ 2 more)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.certInfo.FormatDNSNames()
			if result != tt.expected {
				t.Errorf("FormatDNSNames() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGetColorCode(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected string
	}{
		{
			name:     "Expired - red color",
			status:   "expired",
			expected: "\033[31m",
		},
		{
			name:     "Critical - red color",
			status:   "critical",
			expected: "\033[31m",
		},
		{
			name:     "Expiring soon - yellow color",
			status:   "expiring-soon",
			expected: "\033[33m",
		},
		{
			name:     "Valid - green color",
			status:   "valid",
			expected: "\033[32m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certInfo := CertificateInfo{Status: tt.status}
			result := certInfo.GetColorCode()
			if result != tt.expected {
				t.Errorf("GetColorCode() for status %q = %q, expected %q",
					tt.status, result, tt.expected)
			}
		})
	}
}

// Helper function to generate a test certificate
func generateTestCertificate(dnsNames []string, notBefore, notAfter time.Time) ([]byte, error) {
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, nil
}

func TestParseCertificate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		certData      []byte
		expectError   bool
		expectedCN    string
		expectedDNS   []string
		checkExpiry   bool
		expectedAfter time.Time
	}{
		{
			name: "Valid certificate with DNS names",
			certData: func() []byte {
				cert, _ := generateTestCertificate(
					[]string{"example.com", "www.example.com"},
					now,
					now.Add(365*24*time.Hour),
				)
				return cert
			}(),
			expectError: false,
			expectedCN:  "test.example.com",
			expectedDNS: []string{"example.com", "www.example.com"},
			checkExpiry: true,
		},
		{
			name: "Certificate without DNS names uses CN",
			certData: func() []byte {
				cert, _ := generateTestCertificate(
					[]string{},
					now,
					now.Add(365*24*time.Hour),
				)
				return cert
			}(),
			expectError: false,
			expectedCN:  "test.example.com",
			expectedDNS: []string{"test.example.com"},
		},
		{
			name:        "Invalid PEM data",
			certData:    []byte("not a valid PEM"),
			expectError: true,
		},
		{
			name: "Invalid certificate type",
			certData: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3V...
-----END RSA PRIVATE KEY-----`),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certInfo, err := parseCertificate(tt.certData)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if certInfo.CommonName != tt.expectedCN {
				t.Errorf("CommonName = %q, expected %q", certInfo.CommonName, tt.expectedCN)
			}

			if len(certInfo.DNSNames) != len(tt.expectedDNS) {
				t.Errorf("DNSNames count = %d, expected %d", len(certInfo.DNSNames), len(tt.expectedDNS))
			} else {
				for i, dns := range tt.expectedDNS {
					if certInfo.DNSNames[i] != dns {
						t.Errorf("DNSNames[%d] = %q, expected %q", i, certInfo.DNSNames[i], dns)
					}
				}
			}

			if tt.checkExpiry {
				// Check that expiry date is in the future
				if certInfo.ExpiryDate.Before(now) {
					t.Errorf("ExpiryDate should be in the future, got %v", certInfo.ExpiryDate)
				}
			}
		})
	}
}

func TestCertificateExpiryCalculation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name              string
		expiryDate        time.Time
		expectedRemaining int
		expectedStatus    string
		tolerance         int // Allow +/- tolerance for time calculation
	}{
		{
			name:              "Expired yesterday",
			expiryDate:        now.Add(-24 * time.Hour),
			expectedRemaining: -1,
			expectedStatus:    "expired",
			tolerance:         0,
		},
		{
			name:              "Expires in 5 days",
			expiryDate:        now.Add(5 * 24 * time.Hour),
			expectedRemaining: 5,
			expectedStatus:    "critical",
			tolerance:         1,
		},
		{
			name:              "Expires in 15 days",
			expiryDate:        now.Add(15 * 24 * time.Hour),
			expectedRemaining: 15,
			expectedStatus:    "expiring-soon",
			tolerance:         1,
		},
		{
			name:              "Expires in 60 days",
			expiryDate:        now.Add(60 * 24 * time.Hour),
			expectedRemaining: 60,
			expectedStatus:    "valid",
			tolerance:         1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certInfo := CertificateInfo{
				ExpiryDate: tt.expiryDate,
			}

			daysRemaining := int(time.Until(certInfo.ExpiryDate).Hours() / 24)

			// Check within tolerance
			diff := daysRemaining - tt.expectedRemaining
			if diff < -tt.tolerance || diff > tt.tolerance {
				t.Errorf("Days remaining = %d, expected %d (±%d)", daysRemaining, tt.expectedRemaining, tt.tolerance)
			}

			status := getCertificateStatus(daysRemaining)
			if status != tt.expectedStatus {
				t.Errorf("Status = %q, expected %q", status, tt.expectedStatus)
			}
		})
	}
}

func TestFilterByExpiryDays(t *testing.T) {
	now := time.Now()

	// Create test certificates with different expiry dates
	certs := []CertificateInfo{
		{
			SecretName:    "cert-expired",
			Namespace:     "default",
			ExpiryDate:    now.Add(-1 * 24 * time.Hour),
			DaysRemaining: -1,
			Status:        "expired",
		},
		{
			SecretName:    "cert-critical",
			Namespace:     "default",
			ExpiryDate:    now.Add(5 * 24 * time.Hour),
			DaysRemaining: 5,
			Status:        "critical",
		},
		{
			SecretName:    "cert-expiring",
			Namespace:     "default",
			ExpiryDate:    now.Add(20 * 24 * time.Hour),
			DaysRemaining: 20,
			Status:        "expiring-soon",
		},
		{
			SecretName:    "cert-valid",
			Namespace:     "default",
			ExpiryDate:    now.Add(90 * 24 * time.Hour),
			DaysRemaining: 90,
			Status:        "valid",
		},
	}

	tests := []struct {
		name          string
		expiryDays    int
		expectedCount int
		expectedCerts []string
	}{
		{
			name:          "Filter by 7 days - expired and critical only",
			expiryDays:    7,
			expectedCount: 2,
			expectedCerts: []string{"cert-expired", "cert-critical"},
		},
		{
			name:          "Filter by 30 days - all except valid",
			expiryDays:    30,
			expectedCount: 3,
			expectedCerts: []string{"cert-expired", "cert-critical", "cert-expiring"},
		},
		{
			name:          "Filter by 100 days - all certs",
			expiryDays:    100,
			expectedCount: 4,
			expectedCerts: []string{"cert-expired", "cert-critical", "cert-expiring", "cert-valid"},
		},
		{
			name:          "Filter by 0 days - only expired",
			expiryDays:    0,
			expectedCount: 1,
			expectedCerts: []string{"cert-expired"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := []CertificateInfo{}
			for _, cert := range certs {
				if cert.DaysRemaining <= tt.expiryDays {
					filtered = append(filtered, cert)
				}
			}

			if len(filtered) != tt.expectedCount {
				t.Errorf("Filtered count = %d, expected %d", len(filtered), tt.expectedCount)
			}

			// Verify specific certs are included
			certNames := make(map[string]bool)
			for _, cert := range filtered {
				certNames[cert.SecretName] = true
			}

			for _, expectedName := range tt.expectedCerts {
				if !certNames[expectedName] {
					t.Errorf("Expected cert %q not found in filtered results", expectedName)
				}
			}
		})
	}
}

func TestResetColor(t *testing.T) {
	expected := "\033[0m"
	result := ResetColor()
	if result != expected {
		t.Errorf("ResetColor() = %q, expected %q", result, expected)
	}
}
