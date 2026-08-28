package checks

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

// fakeAPIError is a minimal smithy.APIError usable across the checks tests.
type fakeAPIError string

func (e fakeAPIError) Error() string                 { return string(e) }
func (e fakeAPIError) ErrorCode() string             { return string(e) }
func (e fakeAPIError) ErrorMessage() string          { return string(e) }
func (e fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type fakeAccountSummary struct {
	summary map[string]int32
	err     error
}

func (f fakeAccountSummary) GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &iam.GetAccountSummaryOutput{SummaryMap: f.summary}, nil
}

func TestRootMFA(t *testing.T) {
	tests := []struct {
		name   string
		client fakeAccountSummary
		want   Status
	}{
		{"mfa enabled", fakeAccountSummary{summary: map[string]int32{"AccountMFAEnabled": 1}}, StatusPass},
		{"mfa disabled", fakeAccountSummary{summary: map[string]int32{"AccountMFAEnabled": 0}}, StatusFail},
		{"key missing", fakeAccountSummary{summary: map[string]int32{}}, StatusFail},
		{"api error", fakeAccountSummary{err: errors.New("access denied")}, StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RootMFA{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

var credentialReportHeader = []string{
	"user", "password_enabled", "password_last_used", "password_last_changed",
	"access_key_1_active", "access_key_1_last_used_date", "access_key_1_last_rotated",
	"access_key_2_active", "access_key_2_last_used_date", "access_key_2_last_rotated",
}

func credentialReportCSV(rows ...[]string) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(credentialReportHeader)
	for _, r := range rows {
		_ = w.Write(r)
	}
	w.Flush()
	return buf.Bytes()
}

// fakeCredentialReport implements credentialReportAPI. pendingCalls is the
// number of leading GetCredentialReport calls that report the report as not
// yet ready, mimicking a fresh account with no report generated.
type fakeCredentialReport struct {
	content      []byte
	getErr       error
	generateErr  error
	pendingCalls int
	calls        int
}

func (f *fakeCredentialReport) GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	f.calls++
	if f.calls <= f.pendingCalls {
		return nil, fakeAPIError("ReportInProgress")
	}
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &iam.GetCredentialReportOutput{Content: f.content}, nil
}

func (f *fakeCredentialReport) GenerateCredentialReport(ctx context.Context, params *iam.GenerateCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	if f.generateErr != nil {
		return nil, f.generateErr
	}
	return &iam.GenerateCredentialReportOutput{}, nil
}

func TestUnusedCredentials(t *testing.T) {
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	recent := now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	stale := now.Add(-100 * 24 * time.Hour).Format(time.RFC3339)

	tests := []struct {
		name   string
		report *fakeCredentialReport
		want   Status
	}{
		{
			name: "recently used password and unused keys",
			report: &fakeCredentialReport{content: credentialReportCSV(
				[]string{"alice", "true", recent, stale, "false", "N/A", "N/A", "false", "N/A", "N/A"},
			)},
			want: StatusPass,
		},
		{
			name: "stale password",
			report: &fakeCredentialReport{content: credentialReportCSV(
				[]string{"bob", "true", stale, stale, "false", "N/A", "N/A", "false", "N/A", "N/A"},
			)},
			want: StatusFail,
		},
		{
			name: "access key never used but rotated long ago",
			report: &fakeCredentialReport{content: credentialReportCSV(
				[]string{"carol", "false", "N/A", "N/A", "true", "N/A", stale, "false", "N/A", "N/A"},
			)},
			want: StatusFail,
		},
		{
			name: "access key never used, rotated recently",
			report: &fakeCredentialReport{content: credentialReportCSV(
				[]string{"dan", "false", "N/A", "N/A", "true", "no_information", recent, "false", "N/A", "N/A"},
			)},
			want: StatusPass,
		},
		{
			name:   "report not yet generated, generated after polling",
			report: &fakeCredentialReport{pendingCalls: 1, content: credentialReportCSV([]string{"eve", "false", "N/A", "N/A", "false", "N/A", "N/A", "false", "N/A", "N/A"})},
			want:   StatusPass,
		},
		{
			name:   "api error",
			report: &fakeCredentialReport{getErr: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := UnusedCredentials{client: tt.report, now: now, pollInterval: 0}
			got := c.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

type fakeListPolicies struct {
	policies    []iamtypes.Policy
	versions    map[string]string // policy ARN -> URL-encoded document
	listErr     error
	versionErrs map[string]error
}

func (f fakeListPolicies) ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &iam.ListPoliciesOutput{Policies: f.policies}, nil
}

func (f fakeListPolicies) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	arn := aws.ToString(params.PolicyArn)
	if err, ok := f.versionErrs[arn]; ok {
		return nil, err
	}
	doc := f.versions[arn]
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(doc)}}, nil
}

func testPolicy(name, arn string) iamtypes.Policy {
	return iamtypes.Policy{
		PolicyName:       aws.String(name),
		Arn:              aws.String(arn),
		DefaultVersionId: aws.String("v1"),
	}
}

func encodedDoc(t *testing.T, statement string) string {
	t.Helper()
	return url.QueryEscape(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%s]}`, statement))
}

func TestFullAdminPolicies(t *testing.T) {
	tests := []struct {
		name   string
		client fakeListPolicies
		want   Status
	}{
		{
			name: "scoped policy passes",
			client: fakeListPolicies{
				policies: []iamtypes.Policy{testPolicy("scoped", "arn:scoped")},
				versions: map[string]string{
					"arn:scoped": encodedDoc(t, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`),
				},
			},
			want: StatusPass,
		},
		{
			name: "full admin policy string form",
			client: fakeListPolicies{
				policies: []iamtypes.Policy{testPolicy("admin", "arn:admin")},
				versions: map[string]string{
					"arn:admin": encodedDoc(t, `{"Effect":"Allow","Action":"*","Resource":"*"}`),
				},
			},
			want: StatusFail,
		},
		{
			name: "full admin policy array form",
			client: fakeListPolicies{
				policies: []iamtypes.Policy{testPolicy("admin", "arn:admin")},
				versions: map[string]string{
					"arn:admin": encodedDoc(t, `{"Effect":"Allow","Action":["*","other:Action"],"Resource":["*"]}`),
				},
			},
			want: StatusFail,
		},
		{
			name: "deny effect with wildcard is not admin",
			client: fakeListPolicies{
				policies: []iamtypes.Policy{testPolicy("deny", "arn:deny")},
				versions: map[string]string{
					"arn:deny": encodedDoc(t, `{"Effect":"Deny","Action":"*","Resource":"*"}`),
				},
			},
			want: StatusPass,
		},
		{
			name:   "list policies error",
			client: fakeListPolicies{listErr: errors.New("access denied")},
			want:   StatusError,
		},
		{
			name: "get policy version error",
			client: fakeListPolicies{
				policies:    []iamtypes.Policy{testPolicy("admin", "arn:admin")},
				versionErrs: map[string]error{"arn:admin": errors.New("access denied")},
			},
			want: StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FullAdminPolicies{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

type fakePasswordPolicy struct {
	policy *iamtypes.PasswordPolicy
	err    error
}

func (f fakePasswordPolicy) GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: f.policy}, nil
}

func TestPasswordPolicy(t *testing.T) {
	tests := []struct {
		name   string
		client fakePasswordPolicy
		want   Status
	}{
		{
			name: "meets requirements",
			client: fakePasswordPolicy{policy: &iamtypes.PasswordPolicy{
				MinimumPasswordLength:   aws.Int32(14),
				PasswordReusePrevention: aws.Int32(24),
			}},
			want: StatusPass,
		},
		{
			name: "length too short",
			client: fakePasswordPolicy{policy: &iamtypes.PasswordPolicy{
				MinimumPasswordLength:   aws.Int32(8),
				PasswordReusePrevention: aws.Int32(24),
			}},
			want: StatusFail,
		},
		{
			name:   "no policy set",
			client: fakePasswordPolicy{err: fakeAPIError("NoSuchEntity")},
			want:   StatusFail,
		},
		{
			name:   "api error",
			client: fakePasswordPolicy{err: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PasswordPolicy{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}
