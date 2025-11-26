package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
)

// HTTPClient interface for mocking HTTP requests in tests
type HTTPClient interface {
	Post(url, contentType string, body *bytes.Buffer) (*http.Response, error)
}

// DefaultHTTPClient wraps the standard http client
type DefaultHTTPClient struct{}

func (c *DefaultHTTPClient) Post(url, contentType string, body *bytes.Buffer) (*http.Response, error) {
	return http.Post(url, contentType, body)
}

// SlackNotifier handles sending notifications to Slack via webhook
type SlackNotifier struct {
	WebhookURL string
	HTTPClient HTTPClient
}

// NewSlackNotifier creates a new SlackNotifier with the given webhook URL
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		WebhookURL: webhookURL,
		HTTPClient: &DefaultHTTPClient{},
	}
}

// SlackMessage represents the structure of a Slack webhook message
type SlackMessage struct {
	Text        string       `json:"text,omitempty"`
	Blocks      []SlackBlock `json:"blocks,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// SlackBlock represents a Slack block element
type SlackBlock struct {
	Type string      `json:"type"`
	Text *SlackText  `json:"text,omitempty"`
}

// SlackText represents text within a Slack block
type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Attachment represents a Slack message attachment
type Attachment struct {
	Color  string `json:"color,omitempty"`
	Text   string `json:"text,omitempty"`
	Fields []Field `json:"fields,omitempty"`
}

// Field represents a field in a Slack attachment
type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SendAlert sends an audit results alert to Slack
func (s *SlackNotifier) SendAlert(message string, findings aws.AuditResults) error {
	if s.WebhookURL == "" {
		return fmt.Errorf("webhook URL is empty")
	}

	// Build the formatted message
	slackMsg := s.buildSlackMessage(message, findings)

	// Marshal to JSON
	payload, err := json.Marshal(slackMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	// Send HTTP POST request
	resp, err := s.HTTPClient.Post(s.WebhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to send request to Slack: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack API returned non-OK status: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}

// buildSlackMessage constructs a formatted Slack message with findings
func (s *SlackNotifier) buildSlackMessage(message string, findings aws.AuditResults) SlackMessage {
	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")

	// Determine color based on severity (savings amount)
	color := "good" // green
	if findings.TotalPotentialSavings > 500 {
		color = "warning" // yellow/orange
	}
	if findings.TotalPotentialSavings > 1000 {
		color = "danger" // red
	}

	// Build the header text with emojis
	headerText := fmt.Sprintf(":mag: *AWS DevOps Audit Report*\n%s", message)

	// Build detailed findings text
	findingsText := s.formatFindings(findings)

	// Build summary fields
	fields := []Field{
		{
			Title: ":moneybag: Total Potential Savings",
			Value: fmt.Sprintf("*$%.2f/month*", findings.TotalPotentialSavings),
			Short: true,
		},
		{
			Title: ":calendar: Timestamp",
			Value: timestamp,
			Short: true,
		},
	}

	// Add resource count fields
	totalResources := len(findings.UnattachedVolumes) +
		len(findings.UnderutilizedInstances) +
		len(findings.UnderutilizedRDSInstances) +
		len(findings.OrphanedSnapshots) +
		len(findings.UnusedElasticIPs)

	fields = append(fields, Field{
		Title: ":clipboard: Total Resources Found",
		Value: fmt.Sprintf("%d", totalResources),
		Short: true,
	})

	return SlackMessage{
		Text: headerText,
		Attachments: []Attachment{
			{
				Color:  color,
				Text:   findingsText,
				Fields: fields,
			},
		},
	}
}

// formatFindings formats the audit findings with emoji icons and counts
func (s *SlackNotifier) formatFindings(findings aws.AuditResults) string {
	var text string

	// Unattached Volumes
	if len(findings.UnattachedVolumes) > 0 {
		totalCost := 0.0
		for _, vol := range findings.UnattachedVolumes {
			totalCost += vol.MonthlyCost
		}
		text += fmt.Sprintf(":package: *Unattached EBS Volumes:* %d (Est. $%.2f/mo)\n",
			len(findings.UnattachedVolumes), totalCost)
	}

	// Underutilized EC2 Instances
	if len(findings.UnderutilizedInstances) > 0 {
		totalCost := 0.0
		for _, inst := range findings.UnderutilizedInstances {
			totalCost += inst.MonthlyCost
		}
		text += fmt.Sprintf(":computer: *Underutilized EC2 Instances:* %d (Est. $%.2f/mo)\n",
			len(findings.UnderutilizedInstances), totalCost)
	}

	// Underutilized RDS Instances
	if len(findings.UnderutilizedRDSInstances) > 0 {
		totalCost := 0.0
		for _, rds := range findings.UnderutilizedRDSInstances {
			totalCost += rds.MonthlyCost
		}
		text += fmt.Sprintf(":database: *Underutilized RDS Instances:* %d (Est. $%.2f/mo)\n",
			len(findings.UnderutilizedRDSInstances), totalCost)
	}

	// Orphaned Snapshots
	if len(findings.OrphanedSnapshots) > 0 {
		totalCost := 0.0
		for _, snap := range findings.OrphanedSnapshots {
			totalCost += snap.MonthlyCost
		}
		text += fmt.Sprintf(":camera: *Orphaned Snapshots:* %d (Est. $%.2f/mo)\n",
			len(findings.OrphanedSnapshots), totalCost)
	}

	// Unused Elastic IPs
	if len(findings.UnusedElasticIPs) > 0 {
		totalCost := 0.0
		for _, eip := range findings.UnusedElasticIPs {
			totalCost += eip.MonthlyCost
		}
		text += fmt.Sprintf(":globe_with_meridians: *Unused Elastic IPs:* %d (Est. $%.2f/mo)\n",
			len(findings.UnusedElasticIPs), totalCost)
	}

	if text == "" {
		text = ":white_check_mark: No issues found! Your AWS environment looks clean."
	}

	return text
}
