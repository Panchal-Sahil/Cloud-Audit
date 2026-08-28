package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
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

// bucketEncryptionAPI is the slice of the S3 client that BucketEncryption needs.
type bucketEncryptionAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
}

// BucketEncryption implements CIS 2.1.1: every S3 bucket must have default
// server-side encryption configured.
type BucketEncryption struct {
	client bucketEncryptionAPI
}

func (BucketEncryption) ID() string         { return "S3-2" }
func (BucketEncryption) Title() string      { return "All S3 buckets have default encryption (CIS 2.1.1)" }
func (BucketEncryption) Severity() Severity { return SeverityHigh }

func (c BucketEncryption) Run(ctx context.Context) Result {
	buckets, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return errResult(fmt.Errorf("s3:ListBuckets: %w", err))
	}
	if len(buckets.Buckets) == 0 {
		return skip("account has no buckets")
	}

	var unencrypted []string
	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)
		_, err := c.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
		switch {
		case isNoSSEConfig(err):
			unencrypted = append(unencrypted, fmt.Sprintf("%s: no default encryption configured", name))
		case err != nil:
			unencrypted = append(unencrypted, fmt.Sprintf("%s: could not read encryption configuration: %v", name, err))
		}
	}
	if len(unencrypted) > 0 {
		return fail(unencrypted...)
	}
	return pass(fmt.Sprintf("all %d buckets have default encryption", len(buckets.Buckets)))
}

func isNoSSEConfig(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
}

// bucketLoggingAPI is the slice of the S3 client that BucketLogging needs.
type bucketLoggingAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
}

// BucketLogging implements the check that every S3 bucket has server access
// logging enabled.
type BucketLogging struct {
	client bucketLoggingAPI
}

func (BucketLogging) ID() string         { return "S3-3" }
func (BucketLogging) Title() string      { return "S3 buckets have server access logging enabled" }
func (BucketLogging) Severity() Severity { return SeverityLow }

func (c BucketLogging) Run(ctx context.Context) Result {
	buckets, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return errResult(fmt.Errorf("s3:ListBuckets: %w", err))
	}
	if len(buckets.Buckets) == 0 {
		return skip("account has no buckets")
	}

	var unlogged []string
	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)
		out, err := c.client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: b.Name})
		switch {
		case err != nil:
			unlogged = append(unlogged, fmt.Sprintf("%s: could not read logging configuration: %v", name, err))
		case out.LoggingEnabled == nil:
			unlogged = append(unlogged, fmt.Sprintf("%s: server access logging is not enabled", name))
		}
	}
	if len(unlogged) > 0 {
		return fail(unlogged...)
	}
	return pass(fmt.Sprintf("all %d buckets have server access logging enabled", len(buckets.Buckets)))
}
