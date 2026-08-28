// Package checks defines the audit checks and the types they share.
// Every check issues read-only AWS API calls only.
package checks

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Panchal-Sahil/cloudaudit/internal/awsclient"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Status string

const (
	StatusPass  Status = "PASS"
	StatusFail  Status = "FAIL"
	StatusError Status = "ERROR" // the check could not run, e.g. missing permission
	StatusSkip  Status = "SKIP"  // not applicable to this account
)

// Result is the outcome of running a single check.
type Result struct {
	Status Status
	// Evidence lists the per-resource findings behind the status,
	// e.g. "sg-0abc123: allows 0.0.0.0/0 on tcp/22".
	Evidence []string
	Err      error
}

func pass(evidence ...string) Result { return Result{Status: StatusPass, Evidence: evidence} }
func fail(evidence ...string) Result { return Result{Status: StatusFail, Evidence: evidence} }
func skip(evidence ...string) Result { return Result{Status: StatusSkip, Evidence: evidence} }
func errResult(err error) Result     { return Result{Status: StatusError, Err: err} }

// Check is a single CIS benchmark check.
type Check interface {
	ID() string    // e.g. "IAM-1"
	Title() string // human-readable, includes the CIS reference
	Severity() Severity
	Run(ctx context.Context) Result
}

// All constructs every implemented check against the given clients.
func All(c *awsclient.Clients) []Check {
	now := time.Now()
	return []Check{
		RootMFA{client: c.IAM},
		PublicAccessBlock{account: c.S3Control, s3: c.S3, accountID: c.AccountID},
		UnusedCredentials{client: c.IAM, now: now, pollInterval: time.Second},
		FullAdminPolicies{client: c.IAM},
		PasswordPolicy{client: c.IAM},
		BucketEncryption{client: c.S3},
		BucketLogging{client: c.S3},
		OpenSSH{client: c.EC2},
		OpenRDP{client: c.EC2},
		DefaultSGRestricts{client: c.EC2},
		CloudTrailEnabled{client: c.CloudTrail},
		CloudTrailValidation{client: c.CloudTrail},
		EBSEncryption{client: c.EC2},
		RDSEncryption{client: c.RDS},
	}
}

// CheckResult pairs a check's metadata with its outcome.
type CheckResult struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Status   Status   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// RunAll runs every check concurrently (bounded) and returns results in the
// same order as the input. All API calls are read-only, so concurrency is safe.
func RunAll(ctx context.Context, cs []Check) []CheckResult {
	results := make([]CheckResult, len(cs))
	var g errgroup.Group
	g.SetLimit(5)
	for i, c := range cs {
		g.Go(func() error {
			r := c.Run(ctx)
			cr := CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: c.Severity(),
				Status:   r.Status,
				Evidence: r.Evidence,
			}
			if r.Err != nil {
				cr.Error = r.Err.Error()
			}
			results[i] = cr
			return nil
		})
	}
	_ = g.Wait() // check errors are captured in results, never returned
	return results
}
