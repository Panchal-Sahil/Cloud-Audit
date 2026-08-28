package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/smithy-go"
)

// noSuchPAB mimics the API error returned when no public access block exists.
type noSuchPAB struct{}

func (noSuchPAB) Error() string                 { return "NoSuchPublicAccessBlockConfiguration" }
func (noSuchPAB) ErrorCode() string             { return "NoSuchPublicAccessBlockConfiguration" }
func (noSuchPAB) ErrorMessage() string          { return "not configured" }
func (noSuchPAB) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func pabConfig(on bool) *s3controltypes.PublicAccessBlockConfiguration {
	return &s3controltypes.PublicAccessBlockConfiguration{
		BlockPublicAcls: aws.Bool(on), BlockPublicPolicy: aws.Bool(on),
		IgnorePublicAcls: aws.Bool(on), RestrictPublicBuckets: aws.Bool(on),
	}
}

func bucketPABConfig(on bool) *s3types.PublicAccessBlockConfiguration {
	return &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: aws.Bool(on), BlockPublicPolicy: aws.Bool(on),
		IgnorePublicAcls: aws.Bool(on), RestrictPublicBuckets: aws.Bool(on),
	}
}

type fakeAccountPAB struct {
	cfg *s3controltypes.PublicAccessBlockConfiguration
	err error
}

func (f fakeAccountPAB) GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.cfg}, nil
}

type fakeBucketPAB struct {
	buckets []string
	// perBucket maps bucket name to its config; a missing entry means noSuchPAB.
	perBucket map[string]*s3types.PublicAccessBlockConfiguration
	listErr   error
}

func (f fakeBucketPAB) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := &s3.ListBucketsOutput{}
	for _, b := range f.buckets {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(b)})
	}
	return out, nil
}

func (f fakeBucketPAB) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	cfg, ok := f.perBucket[aws.ToString(params.Bucket)]
	if !ok {
		return nil, noSuchPAB{}
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: cfg}, nil
}

func TestPublicAccessBlock(t *testing.T) {
	tests := []struct {
		name    string
		account fakeAccountPAB
		buckets fakeBucketPAB
		want    Status
	}{
		{
			name:    "account-wide block",
			account: fakeAccountPAB{cfg: pabConfig(true)},
			want:    StatusPass,
		},
		{
			name:    "no account block, all buckets block",
			account: fakeAccountPAB{err: noSuchPAB{}},
			buckets: fakeBucketPAB{
				buckets:   []string{"a", "b"},
				perBucket: map[string]*s3types.PublicAccessBlockConfiguration{"a": bucketPABConfig(true), "b": bucketPABConfig(true)},
			},
			want: StatusPass,
		},
		{
			name:    "partial account block, one bucket unconfigured",
			account: fakeAccountPAB{cfg: pabConfig(false)},
			buckets: fakeBucketPAB{
				buckets:   []string{"a", "b"},
				perBucket: map[string]*s3types.PublicAccessBlockConfiguration{"a": bucketPABConfig(true)},
			},
			want: StatusFail,
		},
		{
			name:    "bucket with partial block",
			account: fakeAccountPAB{err: noSuchPAB{}},
			buckets: fakeBucketPAB{
				buckets:   []string{"a"},
				perBucket: map[string]*s3types.PublicAccessBlockConfiguration{"a": bucketPABConfig(false)},
			},
			want: StatusFail,
		},
		{
			name:    "no block anywhere but no buckets",
			account: fakeAccountPAB{err: noSuchPAB{}},
			buckets: fakeBucketPAB{},
			want:    StatusSkip,
		},
		{
			name:    "account api error",
			account: fakeAccountPAB{err: errors.New("access denied")},
			want:    StatusError,
		},
		{
			name:    "list buckets error",
			account: fakeAccountPAB{err: noSuchPAB{}},
			buckets: fakeBucketPAB{listErr: errors.New("access denied")},
			want:    StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := PublicAccessBlock{account: tt.account, s3: tt.buckets, accountID: "123456789012"}
			got := c.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}
