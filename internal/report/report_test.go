package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Panchal-Sahil/cloudaudit/internal/checks"
)

func TestScore(t *testing.T) {
	tests := []struct {
		name    string
		results []checks.CheckResult
		want    float64
	}{
		{"empty", nil, 100},
		{
			"all pass",
			[]checks.CheckResult{
				{Severity: checks.SeverityCritical, Status: checks.StatusPass},
				{Severity: checks.SeverityLow, Status: checks.StatusPass},
			},
			100,
		},
		{
			"critical fail outweighs low pass",
			[]checks.CheckResult{
				{Severity: checks.SeverityCritical, Status: checks.StatusFail}, // 0/10
				{Severity: checks.SeverityLow, Status: checks.StatusPass},      // 1/1
			},
			9.1, // 1/11
		},
		{
			"error and skip excluded from denominator",
			[]checks.CheckResult{
				{Severity: checks.SeverityCritical, Status: checks.StatusError},
				{Severity: checks.SeverityCritical, Status: checks.StatusSkip},
				{Severity: checks.SeverityHigh, Status: checks.StatusPass},
			},
			100,
		},
		{
			"half by weight",
			[]checks.CheckResult{
				{Severity: checks.SeverityHigh, Status: checks.StatusPass}, // 6
				{Severity: checks.SeverityMedium, Status: checks.StatusFail},
				{Severity: checks.SeverityMedium, Status: checks.StatusFail}, // 0/6
			},
			50,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Score(tt.results); got != tt.want {
				t.Errorf("Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAndJSON(t *testing.T) {
	results := []checks.CheckResult{
		{ID: "IAM-1", Severity: checks.SeverityCritical, Status: checks.StatusPass},
		{ID: "S3-1", Severity: checks.SeverityCritical, Status: checks.StatusFail, Evidence: []string{"bucket x is open"}},
		{ID: "ENC-2", Severity: checks.SeverityHigh, Status: checks.StatusSkip},
	}
	rep := New(Meta{Version: "test", AccountID: "123456789012", Region: "us-east-1"}, results)

	if rep.Summary != (Summary{Total: 3, Passed: 1, Failed: 1, Skipped: 1}) {
		t.Errorf("unexpected summary: %+v", rep.Summary)
	}
	if rep.Score != 50 {
		t.Errorf("score = %v, want 50", rep.Score)
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("report JSON does not round-trip: %v", err)
	}
	if len(decoded.Results) != 3 || decoded.Meta.AccountID != "123456789012" {
		t.Errorf("unexpected decoded report: %+v", decoded)
	}
}

func TestPrintTerminal(t *testing.T) {
	rep := New(Meta{}, []checks.CheckResult{
		{ID: "IAM-1", Title: "Root MFA", Severity: checks.SeverityCritical, Status: checks.StatusFail, Evidence: []string{"no MFA"}},
	})
	var buf bytes.Buffer
	PrintTerminal(&buf, rep)
	out := buf.String()
	for _, want := range []string{"IAM-1", "FAIL", "no MFA", "0.0%"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
}
