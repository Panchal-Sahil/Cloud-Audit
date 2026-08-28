package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type fakeAccountSummary struct {
	summary map[string]int32
	err     error
}

func (f fakeAccountSummary) GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &iam.GetAccountSummaryOutput{SummaryMap: f.summary}, nil
}

func TestRootMFA(t *testing.T) {
	tests := []struct {
		name   string
		client fakeAccountSummary
		want   Status
	}{
		{"mfa enabled", fakeAccountSummary{summary: map[string]int32{"AccountMFAEnabled": 1}}, StatusPass},
		{"mfa disabled", fakeAccountSummary{summary: map[string]int32{"AccountMFAEnabled": 0}}, StatusFail},
		{"key missing", fakeAccountSummary{summary: map[string]int32{}}, StatusFail},
		{"api error", fakeAccountSummary{err: errors.New("access denied")}, StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RootMFA{client: tt.client}.Run(context.Background())
			if got.Status != tt.want {
				t.Errorf("status = %s, want %s (evidence %v, err %v)", got.Status, tt.want, got.Evidence, got.Err)
			}
		})
	}
}
