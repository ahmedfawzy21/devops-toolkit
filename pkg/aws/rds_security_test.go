package aws

import "testing"

func TestEOLVersionCheck(t *testing.T) {
	tests := []struct {
		name         string
		engine       string
		version      string
		wantFlagged  bool
		wantSeverity string
	}{
		{"mysql 5.7 EOL", "mysql", "5.7.44", true, "critical"},
		{"mysql 8.0 approaching", "mysql", "8.0.35", true, "warning"},
		{"mysql 8.4 supported", "mysql", "8.4.0", false, ""},
		{"postgres 11 EOL", "postgres", "11.19", true, "critical"},
		{"postgres 12 EOL", "postgres", "12.18", true, "critical"},
		{"postgres 13 EOL", "postgres", "13.15", true, "critical"},
		{"postgres 14 approaching", "postgres", "14.12", true, "warning"},
		{"postgres 15 supported", "postgres", "15.7", false, ""},
		{"aurora-mysql 5.7", "aurora-mysql", "5.7.mysql_aurora.2.11.0", true, "critical"},
		{"aurora-postgresql 14", "aurora-postgresql", "14.9", true, "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, flagged := checkEOLVersion(tt.engine, tt.version)
			if flagged != tt.wantFlagged {
				t.Fatalf("checkEOLVersion(%q, %q) flagged = %v, want %v", tt.engine, tt.version, flagged, tt.wantFlagged)
			}
			if flagged && info.severity != tt.wantSeverity {
				t.Errorf("checkEOLVersion(%q, %q) severity = %q, want %q", tt.engine, tt.version, info.severity, tt.wantSeverity)
			}
		})
	}
}

func TestDevInstanceSkipped(t *testing.T) {
	dev := []string{"db.t3.micro", "db.t2.small"}
	for _, class := range dev {
		if !isDevInstanceClass(class) {
			t.Errorf("isDevInstanceClass(%q) = false, want true (should be skipped in Multi-AZ check)", class)
		}
	}

	prod := []string{"db.m5.large", "db.r6g.xlarge", "db.t3.large"}
	for _, class := range prod {
		if isDevInstanceClass(class) {
			t.Errorf("isDevInstanceClass(%q) = true, want false (should be checked for Multi-AZ)", class)
		}
	}
}

func TestDefaultUsernameDetection(t *testing.T) {
	tests := []struct {
		username string
		want     bool
	}{
		{"admin", true},
		{"root", true},
		{"postgres", true},
		{"mysql", true},
		{"administrator", true},
		{"sa", true},
		{"rdsadmin", true},
		{"appuser", false},
		{"ahmed", false},
	}

	for _, tt := range tests {
		if got := isDefaultMasterUsername(tt.username); got != tt.want {
			t.Errorf("isDefaultMasterUsername(%q) = %v, want %v", tt.username, got, tt.want)
		}
	}
}

func TestInsecureParameterDetection(t *testing.T) {
	tests := []struct {
		name       string
		engine     string
		params     map[string]string
		wantIssues []string
	}{
		{
			name:       "mysql local_infile enabled",
			engine:     "mysql",
			params:     map[string]string{"local_infile": "1"},
			wantIssues: []string{"mysql_local_infile_enabled"},
		},
		{
			name:       "mysql local_infile disabled",
			engine:     "mysql",
			params:     map[string]string{"local_infile": "0"},
			wantIssues: nil,
		},
		{
			name:       "mysql general_log to file",
			engine:     "aurora-mysql",
			params:     map[string]string{"general_log": "1", "log_output": "FILE"},
			wantIssues: []string{"mysql_general_log_to_file"},
		},
		{
			name:       "mysql general_log to table only",
			engine:     "mysql",
			params:     map[string]string{"general_log": "1", "log_output": "TABLE"},
			wantIssues: nil,
		},
		{
			name:       "postgres ssl disabled",
			engine:     "postgres",
			params:     map[string]string{"ssl": "0"},
			wantIssues: []string{"postgres_ssl_disabled"},
		},
		{
			name:       "postgres ssl enabled",
			engine:     "aurora-postgresql",
			params:     map[string]string{"ssl": "1"},
			wantIssues: nil,
		},
		{
			name:       "postgres log_connections disabled",
			engine:     "postgres",
			params:     map[string]string{"log_connections": "0"},
			wantIssues: []string{"postgres_log_connections_disabled"},
		},
		{
			name:       "engine mismatch ignores mysql params",
			engine:     "postgres",
			params:     map[string]string{"local_infile": "1"},
			wantIssues: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := evaluateInsecureParameters(tt.engine, tt.params)

			got := make(map[string]bool, len(issues))
			for _, iss := range issues {
				got[iss.Issue] = true
			}

			if len(issues) != len(tt.wantIssues) {
				t.Fatalf("evaluateInsecureParameters(%q, %v) returned %d issues, want %d", tt.engine, tt.params, len(issues), len(tt.wantIssues))
			}
			for _, want := range tt.wantIssues {
				if !got[want] {
					t.Errorf("evaluateInsecureParameters(%q, %v) missing issue %q", tt.engine, tt.params, want)
				}
			}
		})
	}
}
