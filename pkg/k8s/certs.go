package k8s

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateInfo holds information about a TLS certificate
type CertificateInfo struct {
	SecretName    string
	Namespace     string
	DNSNames      []string
	CommonName    string
	Issuer        string
	ExpiryDate    time.Time
	DaysRemaining int
	Status        string // "valid", "expiring-soon", "critical", "expired"
}

// CertificateResults holds the results of certificate scanning
type CertificateResults struct {
	Certificates   []CertificateInfo
	TotalScanned   int
	ExpiringCount  int
	CriticalCount  int
	ExpiredCount   int
}

// CheckCertificateExpiry scans Kubernetes secrets for TLS certificates and checks expiry
func (h *HealthChecker) CheckCertificateExpiry(ctx context.Context, namespace string, expiryDays int) (*CertificateResults, error) {
	// Get all secrets in the specified namespace(s)
	secrets, err := h.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	results := &CertificateResults{
		Certificates: make([]CertificateInfo, 0),
	}

	for _, secret := range secrets.Items {
		// Only process TLS secrets
		if secret.Type != "kubernetes.io/tls" {
			continue
		}

		results.TotalScanned++

		// Get the certificate data
		certData, ok := secret.Data["tls.crt"]
		if !ok {
			// Skip secrets without tls.crt
			continue
		}

		// Parse the certificate
		certInfo, err := parseCertificate(certData)
		if err != nil {
			// Log error but continue processing other certs
			fmt.Printf("Warning: failed to parse certificate in secret %s/%s: %v\n",
				secret.Namespace, secret.Name, err)
			continue
		}

		// Set secret metadata
		certInfo.SecretName = secret.Name
		certInfo.Namespace = secret.Namespace

		// Calculate days remaining
		daysRemaining := int(time.Until(certInfo.ExpiryDate).Hours() / 24)
		certInfo.DaysRemaining = daysRemaining

		// Determine status
		certInfo.Status = getCertificateStatus(daysRemaining)

		// Count by status
		switch certInfo.Status {
		case "expired":
			results.ExpiredCount++
		case "critical":
			results.CriticalCount++
		case "expiring-soon":
			results.ExpiringCount++
		}

		// Filter by expiry days threshold
		if daysRemaining <= expiryDays {
			results.Certificates = append(results.Certificates, certInfo)
		}
	}

	return results, nil
}

// parseCertificate parses a PEM-encoded certificate and extracts relevant information
func parseCertificate(certData []byte) (CertificateInfo, error) {
	var certInfo CertificateInfo

	// Decode PEM block
	block, _ := pem.Decode(certData)
	if block == nil {
		return certInfo, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return certInfo, fmt.Errorf("PEM block is not a certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certInfo, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract certificate information
	certInfo.CommonName = cert.Subject.CommonName
	certInfo.Issuer = cert.Issuer.CommonName
	certInfo.DNSNames = cert.DNSNames
	certInfo.ExpiryDate = cert.NotAfter

	// If no DNS names, use CN
	if len(certInfo.DNSNames) == 0 && certInfo.CommonName != "" {
		certInfo.DNSNames = []string{certInfo.CommonName}
	}

	return certInfo, nil
}

// getCertificateStatus determines the status based on days remaining
func getCertificateStatus(daysRemaining int) string {
	if daysRemaining < 0 {
		return "expired"
	} else if daysRemaining < 7 {
		return "critical"
	} else if daysRemaining < 30 {
		return "expiring-soon"
	}
	return "valid"
}

// FormatDNSNames formats the DNS names as a comma-separated string
func (c *CertificateInfo) FormatDNSNames() string {
	if len(c.DNSNames) == 0 {
		return "<none>"
	}

	// Limit to first 3 DNS names to avoid cluttering output
	if len(c.DNSNames) > 3 {
		return fmt.Sprintf("%s (+ %d more)",
			strings.Join(c.DNSNames[:3], ", "),
			len(c.DNSNames)-3)
	}

	return strings.Join(c.DNSNames, ", ")
}

// GetColorCode returns the color code for terminal output based on status
func (c *CertificateInfo) GetColorCode() string {
	switch c.Status {
	case "expired", "critical":
		return "\033[31m" // Red
	case "expiring-soon":
		return "\033[33m" // Yellow
	default:
		return "\033[32m" // Green
	}
}

// ResetColor returns the ANSI code to reset color
func ResetColor() string {
	return "\033[0m"
}
