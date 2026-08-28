// Package report renders check results as a terminal summary or JSON document.
package report

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	"github.com/Panchal-Sahil/cloudaudit/internal/checks"
)

var statusColors = map[checks.Status]*color.Color{
	checks.StatusPass:  color.New(color.FgGreen, color.Bold),
	checks.StatusFail:  color.New(color.FgRed, color.Bold),
	checks.StatusError: color.New(color.FgYellow, color.Bold),
	checks.StatusSkip:  color.New(color.FgHiBlack, color.Bold),
}

func scoreColor(score float64) *color.Color {
	switch {
	case score >= 90:
		return color.New(color.FgGreen, color.Bold)
	case score >= 70:
		return color.New(color.FgYellow, color.Bold)
	default:
		return color.New(color.FgRed, color.Bold)
	}
}

// PrintTerminal writes a color-coded summary of the report to w.
func PrintTerminal(w io.Writer, r *Report) {
	for _, res := range r.Results {
		c, ok := statusColors[res.Status]
		if !ok {
			c = color.New()
		}
		fmt.Fprintf(w, "%-6s %-6s [%-8s] %s\n", c.Sprint(res.Status), res.ID, res.Severity, res.Title)
		for _, e := range res.Evidence {
			fmt.Fprintf(w, "         - %s\n", e)
		}
		if res.Error != "" {
			fmt.Fprintf(w, "         ! %s\n", res.Error)
		}
	}

	s := r.Summary
	fmt.Fprintf(w, "\n%d checks: %s passed, %s failed, %d errored, %d skipped\n",
		s.Total,
		statusColors[checks.StatusPass].Sprint(s.Passed),
		statusColors[checks.StatusFail].Sprint(s.Failed),
		s.Errored, s.Skipped)
	fmt.Fprintf(w, "Compliance score: %s\n", scoreColor(r.Score).Sprintf("%.1f%%", r.Score))
}
