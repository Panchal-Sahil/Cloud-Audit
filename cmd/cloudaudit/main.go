package main

import (
	"errors"
	"os"

	"github.com/Panchal-Sahil/cloudaudit/internal/cli"
)

func main() {
	err := cli.Execute()
	switch {
	case err == nil:
	case errors.As(err, &cli.ChecksFailedError{}):
		os.Exit(2)
	default:
		os.Exit(1)
	}
}
