package checks

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

// accountSummaryAPI is the slice of the IAM client that RootMFA needs.
type accountSummaryAPI interface {
	GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
}

// RootMFA implements CIS 1.5: MFA must be enabled for the root account.
type RootMFA struct {
	client accountSummaryAPI
}

func (RootMFA) ID() string         { return "IAM-1" }
func (RootMFA) Title() string      { return "Root account has MFA enabled (CIS 1.5)" }
func (RootMFA) Severity() Severity { return SeverityCritical }

func (c RootMFA) Run(ctx context.Context) Result {
	out, err := c.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return errResult(fmt.Errorf("iam:GetAccountSummary: %w", err))
	}
	if out.SummaryMap["AccountMFAEnabled"] == 1 {
		return pass("root account MFA is enabled")
	}
	return fail("root account does not have MFA enabled")
}

const credentialMaxAge = 45 * 24 * time.Hour

// credentialReportAPI is the slice of the IAM client that UnusedCredentials needs.
type credentialReportAPI interface {
	GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	GenerateCredentialReport(ctx context.Context, params *iam.GenerateCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
}

// UnusedCredentials implements CIS 1.12: passwords and access keys must be
// used at least once every 45 days.
type UnusedCredentials struct {
	client       credentialReportAPI
	now          time.Time
	pollInterval time.Duration
}

func (UnusedCredentials) ID() string         { return "IAM-2" }
func (UnusedCredentials) Title() string      { return "No credentials unused for 45+ days (CIS 1.12)" }
func (UnusedCredentials) Severity() Severity { return SeverityMedium }

func (c UnusedCredentials) Run(ctx context.Context) Result {
	content, err := c.fetchReport(ctx)
	if err != nil {
		return errResult(err)
	}

	records, err := csv.NewReader(bytes.NewReader(content)).ReadAll()
	if err != nil {
		return errResult(fmt.Errorf("parsing credential report: %w", err))
	}
	if len(records) < 2 {
		return skip("credential report has no users")
	}

	col := make(map[string]int, len(records[0]))
	for i, h := range records[0] {
		col[h] = i
	}
	cell := func(row []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}

	var stale []string
	for _, row := range records[1:] {
		user := cell(row, "user")
		if cell(row, "password_enabled") == "true" && c.isStale(cell(row, "password_last_used"), cell(row, "password_last_changed")) {
			stale = append(stale, fmt.Sprintf("%s: password unused for 45+ days", user))
		}
		for _, n := range [...]string{"1", "2"} {
			if cell(row, "access_key_"+n+"_active") == "true" && c.isStale(cell(row, "access_key_"+n+"_last_used_date"), cell(row, "access_key_"+n+"_last_rotated")) {
				stale = append(stale, fmt.Sprintf("%s: access key %s unused for 45+ days", user, n))
			}
		}
	}
	if len(stale) > 0 {
		return fail(stale...)
	}
	return pass("no credentials unused for 45+ days")
}

// isStale reports whether a credential is considered stale: last used more
// than 45 days ago, or never used and set more than 45 days ago.
func (c UnusedCredentials) isStale(lastUsed, setAt string) bool {
	if t, ok := parseReportTime(lastUsed); ok {
		return c.now.Sub(t) > credentialMaxAge
	}
	if t, ok := parseReportTime(setAt); ok {
		return c.now.Sub(t) > credentialMaxAge
	}
	return false
}

// parseReportTime parses an RFC3339 credential report cell, treating the
// report's placeholder values ("N/A", "no_information", "not_supported") and
// any other unparseable value as unknown rather than an error.
func parseReportTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// fetchReport retrieves the IAM credential report, generating one first if
// none exists yet or the existing one has expired.
func (c UnusedCredentials) fetchReport(ctx context.Context) ([]byte, error) {
	out, err := c.client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err == nil {
		return out.Content, nil
	}
	if !isReportPending(err) {
		return nil, fmt.Errorf("iam:GetCredentialReport: %w", err)
	}
	if _, err := c.client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		return nil, fmt.Errorf("iam:GenerateCredentialReport: %w", err)
	}
	for i := 0; i < 5; i++ {
		time.Sleep(c.pollInterval)
		out, err = c.client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			return out.Content, nil
		}
		if !isReportPending(err) {
			return nil, fmt.Errorf("iam:GetCredentialReport: %w", err)
		}
	}
	return nil, fmt.Errorf("iam:GetCredentialReport: report was not ready after retries")
}

func isReportPending(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "ReportNotPresent", "ReportExpired", "ReportInProgress":
		return true
	default:
		return false
	}
}

// listPoliciesAPI is the slice of the IAM client that FullAdminPolicies needs.
type listPoliciesAPI interface {
	iam.ListPoliciesAPIClient
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// FullAdminPolicies implements CIS 1.16: no customer-managed IAM policy
// should grant unrestricted "*" actions on "*" resources.
type FullAdminPolicies struct {
	client listPoliciesAPI
}

func (FullAdminPolicies) ID() string {
	return "IAM-3"
}
func (FullAdminPolicies) Title() string {
	return "No customer-managed policies allow full '*:*' administration (CIS 1.16)"
}
func (FullAdminPolicies) Severity() Severity { return SeverityHigh }

func (c FullAdminPolicies) Run(ctx context.Context) Result {
	paginator := iam.NewListPoliciesPaginator(c.client, &iam.ListPoliciesInput{
		Scope:        iamtypes.PolicyScopeTypeLocal,
		OnlyAttached: true,
	})

	var admin []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return errResult(fmt.Errorf("iam:ListPolicies: %w", err))
		}
		for _, p := range page.Policies {
			isAdmin, err := c.isFullAdmin(ctx, p)
			if err != nil {
				return errResult(err)
			}
			if isAdmin {
				admin = append(admin, fmt.Sprintf("%s: allows Action \"*\" on Resource \"*\"", aws.ToString(p.PolicyName)))
			}
		}
	}
	if len(admin) > 0 {
		return fail(admin...)
	}
	return pass("no customer-managed policy grants full administrative access")
}

func (c FullAdminPolicies) isFullAdmin(ctx context.Context, p iamtypes.Policy) (bool, error) {
	if p.Arn == nil || p.DefaultVersionId == nil {
		return false, nil
	}
	out, err := c.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: p.Arn,
		VersionId: p.DefaultVersionId,
	})
	if err != nil {
		return false, fmt.Errorf("iam:GetPolicyVersion(%s): %w", aws.ToString(p.PolicyName), err)
	}
	if out.PolicyVersion == nil || out.PolicyVersion.Document == nil {
		return false, nil
	}

	// GetPolicyVersion URL-encodes the document per RFC 3986.
	decoded, err := url.QueryUnescape(*out.PolicyVersion.Document)
	if err != nil {
		return false, fmt.Errorf("decoding policy document for %s: %w", aws.ToString(p.PolicyName), err)
	}
	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return false, fmt.Errorf("parsing policy document for %s: %w", aws.ToString(p.PolicyName), err)
	}
	for _, s := range doc.Statement {
		if s.Effect == "Allow" && s.Action.has("*") && s.Resource.has("*") {
			return true, nil
		}
	}
	return false, nil
}

type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string        `json:"Effect"`
	Action   stringOrSlice `json:"Action"`
	Resource stringOrSlice `json:"Resource"`
}

// stringOrSlice unmarshals an IAM policy field that AWS allows to be either a
// single string or a list of strings.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*s = stringOrSlice{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*s = multi
	return nil
}

func (s stringOrSlice) has(v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

const (
	minPasswordLength  = 14
	minReusePrevention = 24
)

// passwordPolicyAPI is the slice of the IAM client that PasswordPolicy needs.
type passwordPolicyAPI interface {
	GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
}

// PasswordPolicy implements CIS 1.8/1.9: the account password policy must
// require passwords of at least 14 characters and prevent reuse of the last
// 24 passwords.
type PasswordPolicy struct {
	client passwordPolicyAPI
}

func (PasswordPolicy) ID() string { return "IAM-4" }
func (PasswordPolicy) Title() string {
	return "Password policy requires length >= 14 and reuse prevention >= 24 (CIS 1.8/1.9)"
}
func (PasswordPolicy) Severity() Severity { return SeverityMedium }

func (c PasswordPolicy) Run(ctx context.Context) Result {
	out, err := c.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		if isNoSuchEntity(err) {
			return fail("no account password policy is set")
		}
		return errResult(fmt.Errorf("iam:GetAccountPasswordPolicy: %w", err))
	}

	pol := out.PasswordPolicy
	var unmet []string
	if pol == nil || pol.MinimumPasswordLength == nil || *pol.MinimumPasswordLength < minPasswordLength {
		unmet = append(unmet, fmt.Sprintf("minimum password length is not at least %d", minPasswordLength))
	}
	if pol == nil || pol.PasswordReusePrevention == nil || *pol.PasswordReusePrevention < minReusePrevention {
		unmet = append(unmet, fmt.Sprintf("password reuse prevention is not at least %d", minReusePrevention))
	}
	if len(unmet) > 0 {
		return fail(unmet...)
	}
	return pass("password policy requires length >= 14 and reuse prevention >= 24")
}

func isNoSuchEntity(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity"
}
