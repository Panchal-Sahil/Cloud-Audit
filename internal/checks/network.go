package checks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// OpenSSH implements CIS 5.2: no security group should allow unrestricted
// ingress to port 22.
type OpenSSH struct {
	client ec2.DescribeSecurityGroupsAPIClient
}

func (OpenSSH) ID() string         { return "NET-1" }
func (OpenSSH) Title() string      { return "No security group allows 0.0.0.0/0 to port 22 (CIS 5.2)" }
func (OpenSSH) Severity() Severity { return SeverityHigh }
func (c OpenSSH) Run(ctx context.Context) Result {
	return checkOpenPort(ctx, c.client, 22)
}

// OpenRDP implements CIS 5.3: no security group should allow unrestricted
// ingress to port 3389.
type OpenRDP struct {
	client ec2.DescribeSecurityGroupsAPIClient
}

func (OpenRDP) ID() string    { return "NET-2" }
func (OpenRDP) Title() string { return "No security group allows 0.0.0.0/0 to port 3389 (CIS 5.3)" }
func (OpenRDP) Severity() Severity {
	return SeverityHigh
}
func (c OpenRDP) Run(ctx context.Context) Result {
	return checkOpenPort(ctx, c.client, 3389)
}

func checkOpenPort(ctx context.Context, client ec2.DescribeSecurityGroupsAPIClient, port int32) Result {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	var open []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return errResult(fmt.Errorf("ec2:DescribeSecurityGroups: %w", err))
		}
		for _, sg := range page.SecurityGroups {
			if ruleOpensPort(sg.IpPermissions, port) {
				open = append(open, fmt.Sprintf("%s: allows 0.0.0.0/0 on tcp/%d", aws.ToString(sg.GroupId), port))
			}
		}
	}
	if len(open) > 0 {
		return fail(open...)
	}
	return pass(fmt.Sprintf("no security group allows 0.0.0.0/0 to port %d", port))
}

func ruleOpensPort(perms []ec2types.IpPermission, port int32) bool {
	for _, p := range perms {
		if isOpenToWorld(p) && portInRange(p, port) {
			return true
		}
	}
	return false
}

func isOpenToWorld(p ec2types.IpPermission) bool {
	for _, r := range p.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, r := range p.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

func portInRange(p ec2types.IpPermission, port int32) bool {
	proto := aws.ToString(p.IpProtocol)
	if proto == "-1" {
		return true
	}
	if proto != "tcp" {
		return false
	}
	// No From/ToPort with tcp means all ports are allowed.
	if p.FromPort == nil || p.ToPort == nil {
		return true
	}
	return *p.FromPort <= port && port <= *p.ToPort
}

// DefaultSGRestricts implements CIS 5.4: default security groups must not
// permit any traffic.
type DefaultSGRestricts struct {
	client ec2.DescribeSecurityGroupsAPIClient
}

func (DefaultSGRestricts) ID() string { return "NET-3" }
func (DefaultSGRestricts) Title() string {
	return "Default security groups restrict all traffic (CIS 5.4)"
}
func (DefaultSGRestricts) Severity() Severity {
	return SeverityMedium
}

func (c DefaultSGRestricts) Run(ctx context.Context) Result {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(c.client, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{{Name: aws.String("group-name"), Values: []string{"default"}}},
	})

	var open []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return errResult(fmt.Errorf("ec2:DescribeSecurityGroups: %w", err))
		}
		for _, sg := range page.SecurityGroups {
			if len(sg.IpPermissions) > 0 || len(sg.IpPermissionsEgress) > 0 {
				open = append(open, fmt.Sprintf("%s: default security group has ingress or egress rules", aws.ToString(sg.GroupId)))
			}
		}
	}
	if len(open) > 0 {
		return fail(open...)
	}
	return pass("all default security groups restrict all traffic")
}
