// Package awsclient resolves AWS credentials through the standard credential
// chain and hands out the service clients the checks need.
package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Clients bundles the per-service AWS clients plus the caller identity
// established by the connectivity preflight.
type Clients struct {
	IAM        *iam.Client
	S3         *s3.Client
	S3Control  *s3control.Client
	EC2        *ec2.Client
	CloudTrail *cloudtrail.Client
	RDS        *rds.Client

	AccountID string
	CallerARN string
	Region    string
}

// New loads configuration from the default credential chain, verifies
// connectivity with sts:GetCallerIdentity, and returns ready-to-use clients.
// region overrides the chain's region when non-empty.
func New(ctx context.Context, region string) (*Clients, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("no AWS region configured: set --region, AWS_REGION, or a region in your AWS profile")
	}

	ident, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("verifying credentials with sts:GetCallerIdentity: %w", err)
	}

	return &Clients{
		IAM:        iam.NewFromConfig(cfg),
		S3:         s3.NewFromConfig(cfg),
		S3Control:  s3control.NewFromConfig(cfg),
		EC2:        ec2.NewFromConfig(cfg),
		CloudTrail: cloudtrail.NewFromConfig(cfg),
		RDS:        rds.NewFromConfig(cfg),
		AccountID:  aws.ToString(ident.Account),
		CallerARN:  aws.ToString(ident.Arn),
		Region:     cfg.Region,
	}, nil
}
