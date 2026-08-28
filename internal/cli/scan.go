package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Panchal-Sahil/cloudaudit/internal/awsclient"
	"github.com/Panchal-Sahil/cloudaudit/internal/checks"
	"github.com/Panchal-Sahil/cloudaudit/internal/report"
)

var (
	outputFormat string
	outputFile   string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all checks against the AWS account and report results",
	RunE: func(cmd *cobra.Command, args []string) error {
		if outputFormat != "text" && outputFormat != "json" {
			return fmt.Errorf("invalid --output %q: must be text or json", outputFormat)
		}
		ctx := cmd.Context()

		clients, err := awsclient.New(ctx, region)
		if err != nil {
			return fmt.Errorf("connecting to AWS: %w", err)
		}

		if outputFormat == "text" {
			fmt.Fprintf(cmd.OutOrStdout(), "Auditing account %s as %s (region %s)\n\n",
				clients.AccountID, clients.CallerARN, clients.Region)
		}

		results := checks.RunAll(ctx, checks.All(clients))
		rep := report.New(report.Meta{
			Version:   version,
			AccountID: clients.AccountID,
			CallerARN: clients.CallerARN,
			Region:    clients.Region,
		}, results)

		if outputFormat == "json" {
			if err := report.WriteJSON(cmd.OutOrStdout(), rep); err != nil {
				return err
			}
		} else {
			report.PrintTerminal(cmd.OutOrStdout(), rep)
		}

		if outputFile != "" {
			if err := writeReportFile(outputFile, rep); err != nil {
				return fmt.Errorf("writing report file: %w", err)
			}
		}

		if rep.Summary.Failed > 0 {
			return ChecksFailedError{Failed: rep.Summary.Failed, Total: rep.Summary.Total}
		}
		return nil
	},
}

// ChecksFailedError distinguishes compliance findings (exit code 2) from
// operational errors (exit code 1).
type ChecksFailedError struct {
	Failed, Total int
}

func (e ChecksFailedError) Error() string {
	return fmt.Sprintf("%d of %d checks failed", e.Failed, e.Total)
}

func writeReportFile(path string, rep *report.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := report.WriteJSON(f, rep); err != nil {
		f.Close() //nolint:errcheck // the write error is the one worth reporting
		return err
	}
	return f.Close()
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "output format: text or json")
	scanCmd.Flags().StringVar(&outputFile, "out", "", "also write the JSON report to a file")
	rootCmd.AddCommand(scanCmd)
}
