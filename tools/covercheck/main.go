// Command covercheck enforces the per-package coverage targets of the
// Definition of Done and prints a Markdown table (for $GITHUB_STEP_SUMMARY).
//
// Usage: go run ./tools/covercheck -profile coverage.out
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

const modulePath = "github.com/brennocm/escalint"

// thresholds mirrors section 5 of the spec. Packages that do not exist yet are
// simply absent from the profile and are not checked.
var thresholds = map[string]float64{
	"internal/eval":     90,
	"internal/match":    90,
	"internal/analysis": 85,
	"internal/graph":    85,
	"internal/rules":    85,
	"internal/engine":   85,
	"internal/report":   85,
	"internal/redact":   85,
	"internal/suppress": 85,
	"internal/server":   85,
}

const totalThreshold = 80

type counts struct {
	statements int
	covered    int
}

func (c counts) percent() float64 {
	if c.statements == 0 {
		return 100
	}
	return 100 * float64(c.covered) / float64(c.statements)
}

func main() {
	profile := flag.String("profile", "coverage.out", "coverage profile written by go test -coverprofile")
	flag.Parse()
	os.Exit(run(*profile, os.Stdout, os.Stderr))
}

// run returns the exit code: 0 all targets met, 1 a target missed, 2 error.
func run(profile string, stdout, stderr io.Writer) int {
	f, err := os.Open(profile) // #nosec G304 -- path comes from the developer's own command line
	if err != nil {
		fmt.Fprintf(stderr, "covercheck: %v\n", err)
		return 2
	}
	defer f.Close()

	perPackage, err := parseProfile(f)
	if err != nil {
		fmt.Fprintf(stderr, "covercheck: %v\n", err)
		return 2
	}
	if !report(stdout, perPackage) {
		return 1
	}
	return 0
}

// parseProfile aggregates statements per package. A block can appear more than
// once (one line per test binary); a block counts as covered if any line has a
// non-zero hit count.
func parseProfile(r io.Reader) (map[string]counts, error) {
	type block struct {
		pkg        string
		statements int
		covered    bool
	}
	blocks := map[string]*block{}
	scanner := bufio.NewScanner(r)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if !strings.HasPrefix(line, "mode:") {
				return nil, errors.New("not a coverage profile: missing mode line")
			}
			continue
		}
		if line == "" {
			continue
		}
		// file.go:12.3,14.5 2 1  =>  location, statements, hit count
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed profile line %q", line)
		}
		statements, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("malformed statement count in %q: %w", line, err)
		}
		hits, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("malformed hit count in %q: %w", line, err)
		}
		file, _, ok := strings.Cut(fields[0], ":")
		if !ok {
			return nil, fmt.Errorf("malformed location in %q", line)
		}
		pkg := strings.TrimPrefix(strings.TrimPrefix(path.Dir(file), modulePath), "/")
		b, seen := blocks[fields[0]]
		if !seen {
			b = &block{pkg: pkg, statements: statements}
			blocks[fields[0]] = b
		}
		b.covered = b.covered || hits > 0
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	result := map[string]counts{}
	for _, b := range blocks {
		c := result[b.pkg]
		c.statements += b.statements
		if b.covered {
			c.covered += b.statements
		}
		result[b.pkg] = c
	}
	return result, nil
}

// report writes the Markdown table and returns false if any target is missed.
func report(w io.Writer, perPackage map[string]counts) bool {
	names := make([]string, 0, len(perPackage))
	for name := range perPackage {
		names = append(names, name)
	}
	sort.Strings(names)

	ok := true
	var total counts
	fmt.Fprintln(w, "| Package | Coverage | Target | Status |")
	fmt.Fprintln(w, "| --- | ---: | ---: | --- |")
	for _, name := range names {
		c := perPackage[name]
		total.statements += c.statements
		total.covered += c.covered
		target, hasTarget := thresholds[name]
		status, targetText := "—", "—"
		if hasTarget {
			targetText = fmt.Sprintf("%.0f%%", target)
			status = "pass"
			if c.percent() < target {
				status = "**FAIL**"
				ok = false
			}
		}
		fmt.Fprintf(w, "| `%s` | %.1f%% | %s | %s |\n", name, c.percent(), targetText, status)
	}
	totalStatus := "pass"
	if total.percent() < totalThreshold {
		totalStatus = "**FAIL**"
		ok = false
	}
	fmt.Fprintf(w, "| **total** | %.1f%% | %d%% | %s |\n", total.percent(), totalThreshold, totalStatus)
	return ok
}
