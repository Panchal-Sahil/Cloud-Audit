package report

import (
	"time"

	"github.com/Panchal-Sahil/cloudaudit/internal/checks"
)

// Meta identifies the audited account and the tool run.
type Meta struct {
	Version   string `json:"version"`
	AccountID string `json:"account_id"`
	CallerARN string `json:"caller_arn"`
	Region    string `json:"region"`
}

// Summary counts results by status.
type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Errored int `json:"errored"`
	Skipped int `json:"skipped"`
}

// Report is the complete outcome of a scan.
type Report struct {
	Tool      string               `json:"tool"`
	Meta      Meta                 `json:"meta"`
	Timestamp time.Time            `json:"timestamp"`
	Score     float64              `json:"score"`
	Summary   Summary              `json:"summary"`
	Results   []checks.CheckResult `json:"results"`
}

// New assembles a Report, computing the summary and severity-weighted score.
func New(meta Meta, results []checks.CheckResult) *Report {
	r := &Report{
		Tool:      "cloudaudit",
		Meta:      meta,
		Timestamp: time.Now().UTC(),
		Score:     Score(results),
		Results:   results,
	}
	r.Summary.Total = len(results)
	for _, res := range results {
		switch res.Status {
		case checks.StatusPass:
			r.Summary.Passed++
		case checks.StatusFail:
			r.Summary.Failed++
		case checks.StatusError:
			r.Summary.Errored++
		case checks.StatusSkip:
			r.Summary.Skipped++
		}
	}
	return r
}
