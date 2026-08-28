package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Panchal-Sahil/cloudaudit/internal/awsclient"
)

var (
	outputFormat string
	outputFile   string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all checks against the AWS account and report results",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		clients, err := awsclient.New(ctx, region)
		if err != nil {
			return fmt.Errorf("connecting to AWS: %w", err)
		}

		fmt.Printf("Auditing account %s as %s (region %s)\n",
			clients.AccountID, clients.CallerARN, clients.Region)

		// Checks are wired in as they are implemented.
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "output format: text or json")
	scanCmd.Flags().StringVar(&outputFile, "out", "", "write the JSON report to a file")
	rootCmd.AddCommand(scanCmd)
}
