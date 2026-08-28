package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type fakeCloudTrail struct {
	trails     []cttypes.Trail
	trailsErr  error
	logging    map[string]bool
	statusErrs map[string]error
}

func (f fakeCloudTrail) DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	if f.trailsErr != nil {
		return nil, f.trailsErr
	}
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f fakeCloudTrail) GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	arn := aws.ToString(params.Name)
	if err, ok := f.statusErrs[arn]; ok {
		return nil, err
	}
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(f.logging[arn])}, nil
}

func trail(name, arn string, multiRegion bool) cttypes.Trail {
	return cttypes.Trail{
		Name:               aws.String(name),
		TrailARN:           aws.String(arn),
		IsMultiRegionTrail: aws.Bool(multiRegion),
	}
}

func TestCloudTrailEnabled(t *testing.T) {
	tests := []struct {
		name   string
		client fakeCloudTrail
		want   Status
	}{
		{
			name: "multi-region trail logging",
			client: fakeCloudTrail{
				trails:  []cttypes.Trail{trail("main", "arn:main", true)},
				logging: map[string]bool{"arn:main": true},
			},
			want: StatusPass,
		},
		{
			name:   "no trails",
			client: fakeCloudTrail{},
			want:   StatusFail,
		},
		{
			name: "multi-region trail not logging",
			client: fakeCloudTrail{
				trails:  []cttypes.Trail{trail("main", "arn:main", true)},
				logging: map[string]bool{"arn:main": false},
			},
			want: StatusFail,
		},
		{
			name: "only single-region trails",
			client: fakeCloudTrail{
				trails: []cttypes.Trail{trail("regional", "arn:regional", false)},
			},
			want: StatusFail,
		},
		{
			name:   "describe trails error",
			client: fakeCloudTrail{trailsErr: errors.New("access denied")},
			want:   StatusError,
		},
		{
			name: "get trail status error",
			client: fakeCloudTrail{
				trails:     []cttypes.Trail{trail("main", "arn:main", true)},
				statusErrs: map[string]error{"arn:main": errors.New("access denied")},
			},
			want: StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CloudTrailEnabled{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

func TestCloudTrailValidation(t *testing.T) {
	tests := []struct {
		name   string
		client fakeCloudTrail
		want   Status
	}{
		{
			name: "validation enabled",
			client: fakeCloudTrail{trails: []cttypes.Trail{{
				Name: aws.String("main"), LogFileValidationEnabled: aws.Bool(true),
			}}},
			want: StatusPass,
		},
		{
			name: "validation disabled",
			client: fakeCloudTrail{trails: []cttypes.Trail{{
				Name: aws.String("main"), LogFileValidationEnabled: aws.Bool(false),
			}}},
			want: StatusFail,
		},
		{
			name:   "no trails",
			client: fakeCloudTrail{},
			want:   StatusSkip,
		},
		{
			name:   "describe trails error",
			client: fakeCloudTrail{trailsErr: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CloudTrailValidation{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}
