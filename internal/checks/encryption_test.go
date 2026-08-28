package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type fakeEBS struct {
	defaultEnabled bool
	defaultErr     error
	volumes        []ec2types.Volume
	volumesErr     error
}

func (f fakeEBS) GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	if f.defaultErr != nil {
		return nil, f.defaultErr
	}
	return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: aws.Bool(f.defaultEnabled)}, nil
}

func (f fakeEBS) DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if f.volumesErr != nil {
		return nil, f.volumesErr
	}
	return &ec2.DescribeVolumesOutput{Volumes: f.volumes}, nil
}

func TestEBSEncryption(t *testing.T) {
	tests := []struct {
		name   string
		client fakeEBS
		want   Status
	}{
		{
			name: "default on, all volumes encrypted",
			client: fakeEBS{
				defaultEnabled: true,
				volumes:        []ec2types.Volume{{VolumeId: aws.String("vol-1"), Encrypted: aws.Bool(true)}},
			},
			want: StatusPass,
		},
		{
			name:   "default off",
			client: fakeEBS{defaultEnabled: false},
			want:   StatusFail,
		},
		{
			name: "unencrypted volume",
			client: fakeEBS{
				defaultEnabled: true,
				volumes:        []ec2types.Volume{{VolumeId: aws.String("vol-1"), Encrypted: aws.Bool(false)}},
			},
			want: StatusFail,
		},
		{
			name:   "get default error",
			client: fakeEBS{defaultErr: errors.New("access denied")},
			want:   StatusError,
		},
		{
			name:   "describe volumes error",
			client: fakeEBS{defaultEnabled: true, volumesErr: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EBSEncryption{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

type fakeRDSInstances struct {
	instances []rdstypes.DBInstance
	err       error
}

func (f fakeRDSInstances) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

func TestRDSEncryption(t *testing.T) {
	tests := []struct {
		name   string
		client fakeRDSInstances
		want   Status
	}{
		{
			name: "all instances encrypted",
			client: fakeRDSInstances{instances: []rdstypes.DBInstance{
				{DBInstanceIdentifier: aws.String("db-1"), StorageEncrypted: aws.Bool(true)},
			}},
			want: StatusPass,
		},
		{
			name: "unencrypted instance",
			client: fakeRDSInstances{instances: []rdstypes.DBInstance{
				{DBInstanceIdentifier: aws.String("db-1"), StorageEncrypted: aws.Bool(false)},
			}},
			want: StatusFail,
		},
		{
			name:   "no instances",
			client: fakeRDSInstances{},
			want:   StatusSkip,
		},
		{
			name:   "api error",
			client: fakeRDSInstances{err: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RDSEncryption{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}
