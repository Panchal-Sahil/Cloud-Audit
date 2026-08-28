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

// PrintTerminal writes a color-coded summary of the results to w.
func PrintTerminal(w io.Writer, results []checks.CheckResult) {
	counts := map[checks.Status]int{}
	for _, r := range results {
		counts[r.Status]++
		c, ok := statusColors[r.Status]
		if !ok {
			c = color.New()
		}
		fmt.Fprintf(w, "%-6s %-6s [%-8s] %s\n", c.Sprint(r.Status), r.ID, r.Severity, r.Title)
		for _, e := range r.Evidence {
			fmt.Fprintf(w, "         - %s\n", e)
		}
		if r.Error != "" {
			fmt.Fprintf(w, "         ! %s\n", r.Error)
		}
	}

	fmt.Fprintf(w, "\n%d checks: %s passed, %s failed, %d errored, %d skipped\n",
		len(results),
		statusColors[checks.StatusPass].Sprint(counts[checks.StatusPass]),
		statusColors[checks.StatusFail].Sprint(counts[checks.StatusFail]),
		counts[checks.StatusError], counts[checks.StatusSkip])
}
