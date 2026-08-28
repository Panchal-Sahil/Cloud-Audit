package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// ebsEncryptionAPI is the slice of the EC2 client that EBSEncryption needs.
type ebsEncryptionAPI interface {
	ec2.DescribeVolumesAPIClient
	GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
}

// EBSEncryption implements CIS 2.2.1: EBS encryption by default must be on
// and every existing volume must already be encrypted.
type EBSEncryption struct {
	client ebsEncryptionAPI
}

func (EBSEncryption) ID() string { return "ENC-1" }
func (EBSEncryption) Title() string {
	return "EBS encryption by default is on and all volumes are encrypted (CIS 2.2.1)"
}
func (EBSEncryption) Severity() Severity {
	return SeverityHigh
}

func (c EBSEncryption) Run(ctx context.Context) Result {
	def, err := c.client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return errResult(fmt.Errorf("ec2:GetEbsEncryptionByDefault: %w", err))
	}

	var evidence []string
	if !aws.ToBool(def.EbsEncryptionByDefault) {
		evidence = append(evidence, "EBS encryption by default is not enabled")
	}

	paginator := ec2.NewDescribeVolumesPaginator(c.client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return errResult(fmt.Errorf("ec2:DescribeVolumes: %w", err))
		}
		for _, v := range page.Volumes {
			if !aws.ToBool(v.Encrypted) {
				evidence = append(evidence, fmt.Sprintf("%s: volume is not encrypted", aws.ToString(v.VolumeId)))
			}
		}
	}
	if len(evidence) > 0 {
		return fail(evidence...)
	}
	return pass("EBS encryption by default is on and all volumes are encrypted")
}

// RDSEncryption implements CIS 2.3.1: every RDS instance must be encrypted
// at rest.
type RDSEncryption struct {
	client rds.DescribeDBInstancesAPIClient
}

func (RDSEncryption) ID() string         { return "ENC-2" }
func (RDSEncryption) Title() string      { return "RDS instances are encrypted at rest (CIS 2.3.1)" }
func (RDSEncryption) Severity() Severity { return SeverityHigh }

func (c RDSEncryption) Run(ctx context.Context) Result {
	paginator := rds.NewDescribeDBInstancesPaginator(c.client, &rds.DescribeDBInstancesInput{})
	var total int
	var unencrypted []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return errResult(fmt.Errorf("rds:DescribeDBInstances: %w", err))
		}
		total += len(page.DBInstances)
		for _, db := range page.DBInstances {
			if !aws.ToBool(db.StorageEncrypted) {
				unencrypted = append(unencrypted, fmt.Sprintf("%s: not encrypted at rest", aws.ToString(db.DBInstanceIdentifier)))
			}
		}
	}
	if total == 0 {
		return skip("account has no RDS instances")
	}
	if len(unencrypted) > 0 {
		return fail(unencrypted...)
	}
	return pass(fmt.Sprintf("all %d RDS instances are encrypted at rest", total))
}
