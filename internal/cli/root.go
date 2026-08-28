package cli

import (
	"github.com/spf13/cobra"
)

var region string

var rootCmd = &cobra.Command{
	Use:   "cloudaudit",
	Short: "Audit an AWS account against CIS AWS Foundations Benchmark checks",
	Long: `cloudaudit runs a curated set of read-only CIS AWS Foundations Benchmark
checks against an AWS account and produces a scored compliance report.

Credentials are resolved through the standard AWS credential chain
(environment variables, shared credentials file, IAM role).`,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&region, "region", "", "AWS region (defaults to the credential chain's region)")
}
