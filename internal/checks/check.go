// Package checks defines the audit checks and the types they share.
// Every check issues read-only AWS API calls only.
package checks

import (
	"context"

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

func pass(evidence ...string) Result  { return Result{Status: StatusPass, Evidence: evidence} }
func fail(evidence ...string) Result  { return Result{Status: StatusFail, Evidence: evidence} }
func skip(evidence ...string) Result  { return Result{Status: StatusSkip, Evidence: evidence} }
func errResult(err error) Result      { return Result{Status: StatusError, Err: err} }

// Check is a single CIS benchmark check.
type Check interface {
	ID() string       // e.g. "IAM-1"
	Title() string    // human-readable, includes the CIS reference
	Severity() Severity
	Run(ctx context.Context) Result
}

// All constructs every implemented check against the given clients.
func All(c *awsclient.Clients) []Check {
	return []Check{
		// Checks are appended here as they are implemented.
	}
}
