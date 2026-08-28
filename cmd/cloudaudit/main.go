package main

import (
	"os"

	"github.com/Panchal-Sahil/cloudaudit/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
