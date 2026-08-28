package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X ...cli.version=v1.2.3".
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the cloudaudit version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("cloudaudit", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
