package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type accountPublicAccessAPI interface {
	GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

type bucketPublicAccessAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// PublicAccessBlock implements CIS 2.1.4: S3 public access must be blocked,
// either account-wide or on every individual bucket.
type PublicAccessBlock struct {
	account   accountPublicAccessAPI
	s3        bucketPublicAccessAPI
	accountID string
}

func (PublicAccessBlock) ID() string         { return "S3-1" }
func (PublicAccessBlock) Title() string      { return "S3 public access is blocked (CIS 2.1.4)" }
func (PublicAccessBlock) Severity() Severity { return SeverityCritical }

func (c PublicAccessBlock) Run(ctx context.Context) Result {
	// Account-wide block covers every bucket regardless of per-bucket settings.
	acct, err := c.account.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(c.accountID),
	})
	switch {
	case err == nil && allBlockedControl(acct.PublicAccessBlockConfiguration):
		return pass("account-level public access block is fully enabled")
	case err != nil && !isNoSuchPublicAccessBlock(err):
		return errResult(fmt.Errorf("s3control:GetPublicAccessBlock: %w", err))
	}

	// No full account-wide block: every bucket must block on its own.
	buckets, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return errResult(fmt.Errorf("s3:ListBuckets: %w", err))
	}
	if len(buckets.Buckets) == 0 {
		return skip("no account-level public access block, but the account has no buckets")
	}

	var open []string
	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)
		pab, err := c.s3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
		switch {
		case isNoSuchPublicAccessBlock(err):
			open = append(open, fmt.Sprintf("%s: no public access block configured", name))
		case err != nil:
			open = append(open, fmt.Sprintf("%s: could not read public access block: %v", name, err))
		case !allBlockedBucket(pab.PublicAccessBlockConfiguration):
			open = append(open, fmt.Sprintf("%s: public access block is not fully enabled", name))
		}
	}
	if len(open) > 0 {
		return fail(open...)
	}
	return pass(fmt.Sprintf("all %d buckets fully block public access", len(buckets.Buckets)))
}

func allBlockedControl(cfg *s3controltypes.PublicAccessBlockConfiguration) bool {
	return cfg != nil &&
		aws.ToBool(cfg.BlockPublicAcls) && aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.IgnorePublicAcls) && aws.ToBool(cfg.RestrictPublicBuckets)
}

func allBlockedBucket(cfg *s3types.PublicAccessBlockConfiguration) bool {
	return cfg != nil &&
		aws.ToBool(cfg.BlockPublicAcls) && aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.IgnorePublicAcls) && aws.ToBool(cfg.RestrictPublicBuckets)
}

func isNoSuchPublicAccessBlock(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchPublicAccessBlockConfiguration"
}
