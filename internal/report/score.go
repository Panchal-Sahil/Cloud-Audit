package report

import (
	"math"

	"github.com/Panchal-Sahil/cloudaudit/internal/checks"
)

var severityWeights = map[checks.Severity]float64{
	checks.SeverityCritical: 10,
	checks.SeverityHigh:     6,
	checks.SeverityMedium:   3,
	checks.SeverityLow:      1,
}

// Score computes the severity-weighted compliance score as a percentage.
// Only PASS and FAIL results count toward the denominator: an errored check
// proves nothing either way, and a skipped one does not apply to the account.
func Score(results []checks.CheckResult) float64 {
	var earned, possible float64
	for _, r := range results {
		w := severityWeights[r.Severity]
		switch r.Status {
		case checks.StatusPass:
			earned += w
			possible += w
		case checks.StatusFail:
			possible += w
		}
	}
	if possible == 0 {
		return 100
	}
	return math.Round(earned/possible*1000) / 10 // one decimal place
}
