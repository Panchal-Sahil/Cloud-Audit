package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
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
