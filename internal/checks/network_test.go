package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeSecurityGroups struct {
	groups []ec2types.SecurityGroup
	err    error
}

func (f fakeSecurityGroups) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func sgOpenTCP(id string, from, to int32, cidr string) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{
		GroupId: aws.String(id),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(from),
			ToPort:     aws.Int32(to),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String(cidr)}},
		}},
	}
}

func TestOpenSSH(t *testing.T) {
	tests := []struct {
		name   string
		client fakeSecurityGroups
		want   Status
	}{
		{
			name:   "no rules",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{{GroupId: aws.String("sg-1")}}},
			want:   StatusPass,
		},
		{
			name:   "restricted to a single IP",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{sgOpenTCP("sg-1", 22, 22, "10.0.0.1/32")}},
			want:   StatusPass,
		},
		{
			name:   "open to the world on 22",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{sgOpenTCP("sg-1", 22, 22, "0.0.0.0/0")}},
			want:   StatusFail,
		},
		{
			name:   "open to the world on a range including 22",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{sgOpenTCP("sg-1", 0, 65535, "0.0.0.0/0")}},
			want:   StatusFail,
		},
		{
			name: "all protocols open to the world",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{{
				GroupId: aws.String("sg-1"),
				IpPermissions: []ec2types.IpPermission{{
					IpProtocol: aws.String("-1"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
				}},
			}}},
			want: StatusFail,
		},
		{
			name: "open to the world via ipv6",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{{
				GroupId: aws.String("sg-1"),
				IpPermissions: []ec2types.IpPermission{{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int32(22),
					ToPort:     aws.Int32(22),
					Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
				}},
			}}},
			want: StatusFail,
		},
		{
			name:   "api error",
			client: fakeSecurityGroups{err: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OpenSSH{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

func TestOpenRDP(t *testing.T) {
	tests := []struct {
		name   string
		client fakeSecurityGroups
		want   Status
	}{
		{
			name:   "restricted",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{sgOpenTCP("sg-1", 3389, 3389, "10.0.0.1/32")}},
			want:   StatusPass,
		},
		{
			name:   "open to the world on 3389",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{sgOpenTCP("sg-1", 3389, 3389, "0.0.0.0/0")}},
			want:   StatusFail,
		},
		{
			name:   "api error",
			client: fakeSecurityGroups{err: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OpenRDP{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}

func TestDefaultSGRestricts(t *testing.T) {
	tests := []struct {
		name   string
		client fakeSecurityGroups
		want   Status
	}{
		{
			name:   "no rules",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{{GroupId: aws.String("sg-default"), GroupName: aws.String("default")}}},
			want:   StatusPass,
		},
		{
			name: "has ingress rules",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{{
				GroupId:       aws.String("sg-default"),
				GroupName:     aws.String("default"),
				IpPermissions: []ec2types.IpPermission{{IpProtocol: aws.String("-1")}},
			}}},
			want: StatusFail,
		},
		{
			name: "has egress rules",
			client: fakeSecurityGroups{groups: []ec2types.SecurityGroup{{
				GroupId:             aws.String("sg-default"),
				GroupName:           aws.String("default"),
				IpPermissionsEgress: []ec2types.IpPermission{{IpProtocol: aws.String("-1")}},
			}}},
			want: StatusFail,
		},
		{
			name:   "api error",
			client: fakeSecurityGroups{err: errors.New("access denied")},
			want:   StatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DefaultSGRestricts{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}
