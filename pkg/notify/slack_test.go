package notify

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ahmedfawzy/devops-toolkit/pkg/aws"
)

// MockHTTPClient is a mock implementation of HTTPClient for testing
type MockHTTPClient struct {
	Response   *http.Response
	Err        error
	PostCalled bool
	LastURL    string
	LastBody   *bytes.Buffer
}

func (m *MockHTTPClient) Post(url, contentType string, body *bytes.Buffer) (*http.Response, error) {
	m.PostCalled = true
	m.LastURL = url
	m.LastBody = body
	return m.Response, m.Err
}

// Helper function to create a mock response
func mockResponse(statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Body:       http.NoBody,
	}
}

func TestFormatFindings(t *testing.T) {
	tests := []struct {
		name            string
		findings        aws.AuditResults
		expectedStrings []string
		notExpected     []string
	}{
		{
			name: "All resource types with findings",
			findings: aws.AuditResults{
				UnattachedVolumes: []aws.UnattachedVolume{
					{VolumeID: "vol-123", MonthlyCost: 10.0},
					{VolumeID: "vol-456", MonthlyCost: 20.0},
				},
				UnderutilizedInstances: []aws.UnderutilizedInstance{
					{InstanceID: "i-123", MonthlyCost: 50.0},
				},
				UnderutilizedRDSInstances: []aws.UnderutilizedRDSInstance{
					{InstanceID: "db-123", MonthlyCost: 100.0},
				},
				OrphanedSnapshots: []aws.OrphanedSnapshot{
					{SnapshotID: "snap-123", MonthlyCost: 5.0},
				},
				UnusedElasticIPs: []aws.UnusedElasticIP{
					{AllocationID: "eip-123", MonthlyCost: 3.60},
				},
				TotalPotentialSavings: 188.60,
			},
			expectedStrings: []string{
				":package: *Unattached EBS Volumes:* 2 (Est. $30.00/mo)",
				":computer: *Underutilized EC2 Instances:* 1 (Est. $50.00/mo)",
				":database: *Underutilized RDS Instances:* 1 (Est. $100.00/mo)",
				":camera: *Orphaned Snapshots:* 1 (Est. $5.00/mo)",
				":globe_with_meridians: *Unused Elastic IPs:* 1 (Est. $3.60/mo)",
			},
			notExpected: []string{
				":white_check_mark:",
			},
		},
		{
			name: "Only unattached volumes",
			findings: aws.AuditResults{
				UnattachedVolumes: []aws.UnattachedVolume{
					{VolumeID: "vol-123", MonthlyCost: 15.50},
				},
				TotalPotentialSavings: 15.50,
			},
			expectedStrings: []string{
				":package: *Unattached EBS Volumes:* 1 (Est. $15.50/mo)",
			},
			notExpected: []string{
				":computer:",
				":database:",
				":camera:",
				":globe_with_meridians:",
				":white_check_mark:",
			},
		},
		{
			name:     "Empty results - no findings",
			findings: aws.AuditResults{},
			expectedStrings: []string{
				":white_check_mark: No issues found! Your AWS environment looks clean.",
			},
			notExpected: []string{
				":package:",
				":computer:",
				":database:",
				":camera:",
				":globe_with_meridians:",
			},
		},
		{
			name: "Multiple instances of same type",
			findings: aws.AuditResults{
				UnderutilizedInstances: []aws.UnderutilizedInstance{
					{InstanceID: "i-123", MonthlyCost: 50.0},
					{InstanceID: "i-456", MonthlyCost: 75.0},
					{InstanceID: "i-789", MonthlyCost: 25.0},
				},
				TotalPotentialSavings: 150.0,
			},
			expectedStrings: []string{
				":computer: *Underutilized EC2 Instances:* 3 (Est. $150.00/mo)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := &SlackNotifier{}
			result := notifier.formatFindings(tt.findings)

			// Check expected strings are present
			for _, expected := range tt.expectedStrings {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't.\nGot: %s", expected, result)
				}
			}

			// Check unwanted strings are not present
			for _, unexpected := range tt.notExpected {
				if strings.Contains(result, unexpected) {
					t.Errorf("Expected result NOT to contain %q, but it did.\nGot: %s", unexpected, result)
				}
			}
		})
	}
}

func TestBuildSlackMessage(t *testing.T) {
	tests := []struct {
		name                string
		message             string
		findings            aws.AuditResults
		expectedColor       string
		expectedHeaderText  string
		expectedFieldsCount int
		totalResourceCount  int
	}{
		{
			name:    "Low savings - green color",
			message: "Daily audit completed",
			findings: aws.AuditResults{
				UnattachedVolumes:     []aws.UnattachedVolume{{VolumeID: "vol-1", MonthlyCost: 10.0}},
				TotalPotentialSavings: 100.0,
			},
			expectedColor:       "good",
			expectedHeaderText:  ":mag: *AWS DevOps Audit Report*\nDaily audit completed",
			expectedFieldsCount: 3,
			totalResourceCount:  1,
		},
		{
			name:    "Medium savings - warning color",
			message: "Weekly audit",
			findings: aws.AuditResults{
				UnattachedVolumes:     []aws.UnattachedVolume{{VolumeID: "vol-1", MonthlyCost: 300.0}},
				UnusedElasticIPs:      []aws.UnusedElasticIP{{AllocationID: "eip-1", MonthlyCost: 300.0}},
				TotalPotentialSavings: 600.0,
			},
			expectedColor:       "warning",
			expectedHeaderText:  ":mag: *AWS DevOps Audit Report*\nWeekly audit",
			expectedFieldsCount: 3,
			totalResourceCount:  2,
		},
		{
			name:    "High savings - danger color",
			message: "Critical audit findings",
			findings: aws.AuditResults{
				UnderutilizedInstances: []aws.UnderutilizedInstance{
					{InstanceID: "i-1", MonthlyCost: 500.0},
					{InstanceID: "i-2", MonthlyCost: 600.0},
				},
				TotalPotentialSavings: 1100.0,
			},
			expectedColor:       "danger",
			expectedHeaderText:  ":mag: *AWS DevOps Audit Report*\nCritical audit findings",
			expectedFieldsCount: 3,
			totalResourceCount:  2,
		},
		{
			name:    "Empty findings",
			message: "All clear",
			findings: aws.AuditResults{
				TotalPotentialSavings: 0.0,
			},
			expectedColor:       "good",
			expectedHeaderText:  ":mag: *AWS DevOps Audit Report*\nAll clear",
			expectedFieldsCount: 3,
			totalResourceCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := &SlackNotifier{}
			msg := notifier.buildSlackMessage(tt.message, tt.findings)

			// Check header text
			if msg.Text != tt.expectedHeaderText {
				t.Errorf("Expected header text %q, got %q", tt.expectedHeaderText, msg.Text)
			}

			// Check attachments exist
			if len(msg.Attachments) != 1 {
				t.Fatalf("Expected 1 attachment, got %d", len(msg.Attachments))
			}

			attachment := msg.Attachments[0]

			// Check color
			if attachment.Color != tt.expectedColor {
				t.Errorf("Expected color %q, got %q", tt.expectedColor, attachment.Color)
			}

			// Check fields count
			if len(attachment.Fields) != tt.expectedFieldsCount {
				t.Errorf("Expected %d fields, got %d", tt.expectedFieldsCount, len(attachment.Fields))
			}

			// Verify field contents
			for _, field := range attachment.Fields {
				if field.Title == ":clipboard: Total Resources Found" {
					expectedValue := string(rune('0' + tt.totalResourceCount))
					if !strings.Contains(field.Value, expectedValue) {
						t.Errorf("Expected resource count %d in field value, got %q", tt.totalResourceCount, field.Value)
					}
				}
			}
		})
	}
}

func TestSendAlert_EmptyWebhookURL(t *testing.T) {
	notifier := &SlackNotifier{
		WebhookURL: "",
	}

	err := notifier.SendAlert("test message", aws.AuditResults{})

	if err == nil {
		t.Error("Expected error for empty webhook URL, got nil")
	}

	if !strings.Contains(err.Error(), "webhook URL is empty") {
		t.Errorf("Expected error message about empty webhook URL, got: %v", err)
	}
}

func TestSendAlert_Success(t *testing.T) {
	mockClient := &MockHTTPClient{
		Response: mockResponse(http.StatusOK),
		Err:      nil,
	}

	notifier := &SlackNotifier{
		WebhookURL: "https://hooks.slack.com/services/TEST/WEBHOOK",
		HTTPClient: mockClient,
	}

	findings := aws.AuditResults{
		UnattachedVolumes: []aws.UnattachedVolume{
			{VolumeID: "vol-123", MonthlyCost: 10.0},
		},
		TotalPotentialSavings: 10.0,
	}

	err := notifier.SendAlert("Test alert", findings)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if !mockClient.PostCalled {
		t.Error("Expected HTTP POST to be called")
	}

	if mockClient.LastURL != notifier.WebhookURL {
		t.Errorf("Expected URL %q, got %q", notifier.WebhookURL, mockClient.LastURL)
	}
}

func TestSendAlert_HTTPError(t *testing.T) {
	mockClient := &MockHTTPClient{
		Response: nil,
		Err:      errors.New("connection refused"),
	}

	notifier := &SlackNotifier{
		WebhookURL: "https://hooks.slack.com/services/TEST/WEBHOOK",
		HTTPClient: mockClient,
	}

	err := notifier.SendAlert("Test alert", aws.AuditResults{})

	if err == nil {
		t.Error("Expected error when HTTP request fails, got nil")
	}

	if !strings.Contains(err.Error(), "failed to send request to Slack") {
		t.Errorf("Expected error about failed request, got: %v", err)
	}

	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("Expected error to contain underlying error, got: %v", err)
	}
}

func TestSendAlert_NonOKStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"Bad Request", http.StatusBadRequest},
		{"Unauthorized", http.StatusUnauthorized},
		{"Forbidden", http.StatusForbidden},
		{"Not Found", http.StatusNotFound},
		{"Internal Server Error", http.StatusInternalServerError},
		{"Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				Response: mockResponse(tt.statusCode),
				Err:      nil,
			}

			notifier := &SlackNotifier{
				WebhookURL: "https://hooks.slack.com/services/TEST/WEBHOOK",
				HTTPClient: mockClient,
			}

			err := notifier.SendAlert("Test alert", aws.AuditResults{})

			if err == nil {
				t.Errorf("Expected error for status code %d, got nil", tt.statusCode)
			}

			if !strings.Contains(err.Error(), "non-OK status") {
				t.Errorf("Expected error about non-OK status, got: %v", err)
			}

			expectedStatus := string(rune('0' + tt.statusCode/100))
			if !strings.Contains(err.Error(), expectedStatus) {
				t.Errorf("Expected error to contain status code %d, got: %v", tt.statusCode, err)
			}
		})
	}
}

func TestSendAlert_EmptyResults(t *testing.T) {
	mockClient := &MockHTTPClient{
		Response: mockResponse(http.StatusOK),
		Err:      nil,
	}

	notifier := &SlackNotifier{
		WebhookURL: "https://hooks.slack.com/services/TEST/WEBHOOK",
		HTTPClient: mockClient,
	}

	// Empty audit results
	emptyFindings := aws.AuditResults{
		UnattachedVolumes:         []aws.UnattachedVolume{},
		UnderutilizedInstances:    []aws.UnderutilizedInstance{},
		UnderutilizedRDSInstances: []aws.UnderutilizedRDSInstance{},
		OrphanedSnapshots:         []aws.OrphanedSnapshot{},
		UnusedElasticIPs:          []aws.UnusedElasticIP{},
		TotalPotentialSavings:     0.0,
	}

	// Should still send the alert with "no issues found" message
	err := notifier.SendAlert("Scheduled audit completed", emptyFindings)

	if err != nil {
		t.Errorf("Expected no error for empty results, got: %v", err)
	}

	if !mockClient.PostCalled {
		t.Error("Expected HTTP POST to be called even for empty results")
	}

	// Verify the message contains the "no issues found" text
	bodyString := mockClient.LastBody.String()
	if !strings.Contains(bodyString, "white_check_mark") || !strings.Contains(bodyString, "No issues found") {
		t.Error("Expected message to contain 'no issues found' text for empty results")
	}
}

func TestNewSlackNotifier(t *testing.T) {
	webhookURL := "https://hooks.slack.com/services/TEST/WEBHOOK"
	notifier := NewSlackNotifier(webhookURL)

	if notifier.WebhookURL != webhookURL {
		t.Errorf("Expected webhook URL %q, got %q", webhookURL, notifier.WebhookURL)
	}

	if notifier.HTTPClient == nil {
		t.Error("Expected HTTPClient to be initialized, got nil")
	}

	// Verify it's using DefaultHTTPClient
	if _, ok := notifier.HTTPClient.(*DefaultHTTPClient); !ok {
		t.Errorf("Expected HTTPClient to be *DefaultHTTPClient, got %T", notifier.HTTPClient)
	}
}

func TestSlackMessageStructure(t *testing.T) {
	notifier := &SlackNotifier{}

	findings := aws.AuditResults{
		UnattachedVolumes: []aws.UnattachedVolume{
			{
				VolumeID:         "vol-123",
				Size:             100,
				VolumeType:       "gp3",
				AvailabilityZone: "us-east-1a",
				CreateTime:       time.Now(),
				MonthlyCost:      8.0,
			},
		},
		UnderutilizedInstances: []aws.UnderutilizedInstance{
			{
				InstanceID:        "i-123",
				InstanceType:      "t3.small",
				State:             "running",
				AvgCPUUtilization: 2.5,
				MonthlyCost:       18.0,
				LaunchTime:        time.Now(),
			},
		},
		TotalPotentialSavings: 26.0,
	}

	msg := notifier.buildSlackMessage("Structure test", findings)

	// Verify message has required fields
	if msg.Text == "" {
		t.Error("Expected message text to be set")
	}

	if len(msg.Attachments) == 0 {
		t.Fatal("Expected at least one attachment")
	}

	attachment := msg.Attachments[0]

	// Verify attachment has color
	validColors := map[string]bool{"good": true, "warning": true, "danger": true}
	if !validColors[attachment.Color] {
		t.Errorf("Expected valid color (good/warning/danger), got %q", attachment.Color)
	}

	// Verify attachment has text
	if attachment.Text == "" {
		t.Error("Expected attachment text to be set")
	}

	// Verify attachment has fields
	if len(attachment.Fields) < 3 {
		t.Errorf("Expected at least 3 fields, got %d", len(attachment.Fields))
	}

	// Verify field structure
	for i, field := range attachment.Fields {
		if field.Title == "" {
			t.Errorf("Field %d has empty title", i)
		}
		if field.Value == "" {
			t.Errorf("Field %d has empty value", i)
		}
	}
}

func TestFormatFindings_CostAccuracy(t *testing.T) {
	notifier := &SlackNotifier{}

	findings := aws.AuditResults{
		UnattachedVolumes: []aws.UnattachedVolume{
			{VolumeID: "vol-1", MonthlyCost: 10.50},
			{VolumeID: "vol-2", MonthlyCost: 15.75},
			{VolumeID: "vol-3", MonthlyCost: 20.25},
		},
		TotalPotentialSavings: 46.50,
	}

	result := notifier.formatFindings(findings)

	// Should show the sum of all volume costs
	if !strings.Contains(result, "$46.50/mo") {
		t.Errorf("Expected total cost $46.50/mo in result, got: %s", result)
	}

	if !strings.Contains(result, "3 (Est. $46.50/mo)") {
		t.Errorf("Expected count and cost together, got: %s", result)
	}
}
