package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExecute(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantCode: ExitOK, wantStdout: "escalint dev"},
		{name: "version rejects args", args: []string{"version", "extra"}, wantCode: ExitError, wantStderr: "unknown command"},
		{name: "unknown command", args: []string{"nope"}, wantCode: ExitError, wantStderr: `unknown command "nope"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(tc.args, &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %q)", code, tc.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tc.wantStdout)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

func TestErrorsAreSanitizedForTheTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"\x1b[2Jevil"}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit code = %d", code)
	}
	if strings.ContainsRune(stderr.String(), '\x1b') {
		t.Fatalf("raw escape sequence reached stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `\x1b[2Jevil`) {
		t.Errorf("stderr = %q, want the escaped name", stderr.String())
	}
}

func TestCodeErrorSetsExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := NewRootCommand(&stdout, &stderr)
	root.AddCommand(&cobra.Command{
		Use: "fail",
		RunE: func(*cobra.Command, []string) error {
			return &CodeError{Code: ExitFindings}
		},
	})
	root.SetArgs([]string{"fail"})
	err := root.Execute()
	var codeErr *CodeError
	if !errors.As(err, &codeErr) || codeErr.Code != ExitFindings {
		t.Fatalf("Execute() error = %v, want CodeError{%d}", err, ExitFindings)
	}
	if stderr.Len() != 0 {
		t.Errorf("CodeError must not print anything, stderr = %q", stderr.String())
	}
}
