package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/brennocm/escalint/internal/cli"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"escalint": func() { os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr)) },
	})
}

// TestScripts runs testdata/script/*.txtar: commands, flags, exit codes and
// error messages end to end.
func TestScripts(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Setup: func(env *testscript.Env) error {
			env.Setenv("EXAMPLES", filepath.Join(root, "examples"))
			env.Setenv("FIXTURES", filepath.Join(root, "internal", "rules", "testdata"))
			env.Setenv("NO_COLOR", "1")
			env.Setenv("ESCALINT_NOW", "2026-10-23")
			return nil
		},
	})
}
