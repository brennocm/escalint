// Package cli wires the escalint commands together with cobra.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/internal/termsafe"
)

// Exit codes shared by every command (see README "Exit codes").
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// NewRootCommand builds the command tree. Output streams are parameters so
// tests can capture them instead of touching os.Stdout.
func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "escalint",
		Short:         "Static analysis of AWS IAM privilege escalation paths",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newVersionCommand())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := NewRootCommand(stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var codeErr *CodeError
		if errors.As(err, &codeErr) {
			return codeErr.Code
		}
		// Errors can quote snapshot content; never let it reach the
		// terminal raw.
		fmt.Fprintf(stderr, "escalint: %s\n", termsafe.Line(err.Error()))
		return ExitError
	}
	return ExitOK
}

// CodeError lets a command request a specific exit code (for example
// ExitFindings when results exceed --fail-on) without printing an error.
type CodeError struct {
	Code int
}

func (e *CodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}
