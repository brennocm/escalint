// Command escalint analyzes AWS IAM snapshots for privilege escalation paths.
package main

import (
	"os"

	"github.com/brennocm/escalint/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
