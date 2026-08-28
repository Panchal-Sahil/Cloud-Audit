package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// describeTrailsAPI is the slice of the CloudTrail client that CloudTrailValidation needs.
type describeTrailsAPI interface {
	DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
}

// trailStatusAPI is the slice of the CloudTrail client that CloudTrailEnabled needs.
type trailStatusAPI interface {
	describeTrailsAPI
	GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// CloudTrailEnabled implements CIS 3.1: at least one multi-region CloudTrail
// trail must exist and be actively logging.
type CloudTrailEnabled struct {
	client trailStatusAPI
}

func (CloudTrailEnabled) ID() string { return "LOG-1" }
func (CloudTrailEnabled) Title() string {
	return "A multi-region CloudTrail is enabled and logging (CIS 3.1)"
}
func (CloudTrailEnabled) Severity() Severity { return SeverityCritical }

func (c CloudTrailEnabled) Run(ctx context.Context) Result {
	out, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return errResult(fmt.Errorf("cloudtrail:DescribeTrails: %w", err))
	}
	if len(out.TrailList) == 0 {
		return fail("no CloudTrail trails exist")
	}

	var multiRegion []string
	for _, t := range out.TrailList {
		if !aws.ToBool(t.IsMultiRegionTrail) {
			continue
		}
		name := aws.ToString(t.Name)
		multiRegion = append(multiRegion, name)
		status, err := c.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
		if err != nil {
			return errResult(fmt.Errorf("cloudtrail:GetTrailStatus(%s): %w", name, err))
		}
		if aws.ToBool(status.IsLogging) {
			return pass(fmt.Sprintf("%s: multi-region trail is logging", name))
		}
	}
	if len(multiRegion) == 0 {
		return fail("no multi-region CloudTrail trail exists")
	}
	return fail(fmt.Sprintf("multi-region trail(s) %v exist but none are logging", multiRegion))
}

// CloudTrailValidation implements CIS 3.2: CloudTrail log file validation
// must be enabled on every trail.
type CloudTrailValidation struct {
	client describeTrailsAPI
}

func (CloudTrailValidation) ID() string {
	return "LOG-2"
}
func (CloudTrailValidation) Title() string {
	return "CloudTrail log file validation is enabled (CIS 3.2)"
}
func (CloudTrailValidation) Severity() Severity { return SeverityMedium }

func (c CloudTrailValidation) Run(ctx context.Context) Result {
	out, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return errResult(fmt.Errorf("cloudtrail:DescribeTrails: %w", err))
	}
	// LOG-1 already fails when there are no trails at all.
	if len(out.TrailList) == 0 {
		return skip("no CloudTrail trails exist")
	}

	var noValidation []string
	for _, t := range out.TrailList {
		if !aws.ToBool(t.LogFileValidationEnabled) {
			noValidation = append(noValidation, fmt.Sprintf("%s: log file validation is not enabled", aws.ToString(t.Name)))
		}
	}
	if len(noValidation) > 0 {
		return fail(noValidation...)
	}
	return pass(fmt.Sprintf("all %d trails have log file validation enabled", len(out.TrailList)))
}
