package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/diff"
	"github.com/brennocm/escalint/internal/report"
)

func newAnalyzeCommand() *cobra.Command {
	var f analysisFlags
	var out string
	cmd := &cobra.Command{
		Use:   "analyze <snapshot>",
		Short: "Write analysis.json, the full graph and findings (the web UI contract)",
		Long: "Analyze a snapshot (the output of `aws iam get-account-authorization-details` or of\n" +
			"`escalint collect`; \"-\" reads stdin) and write analysis.json. Its JSON Schema is\n" +
			"printed by `escalint schema`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := f.load(cmd, args[0])
			if err != nil {
				return err
			}
			if err := f.finish(l); err != nil {
				return err
			}
			return writeAnalysis(cmd, out, l.analysis)
		},
	}
	f.register(cmd)
	cmd.Flags().StringVarP(&out, "output", "o", "", "write to a file (mode 0600) instead of stdout")
	return cmd
}

// writeAnalysis streams the document to the output: on large accounts it is
// gigabytes that need not be buffered first.
func writeAnalysis(cmd *cobra.Command, path string, a *contract.Analysis) error {
	o, err := openOutput(cmd, path)
	if err != nil {
		return err
	}
	werr := contract.Encode(o.w, a)
	if cerr := o.close(werr != nil); werr == nil {
		werr = cerr
	}
	return werr
}

func writeAll(cmd *cobra.Command, path string, data []byte) error {
	o, err := openOutput(cmd, path)
	if err != nil {
		return err
	}
	_, werr := o.w.Write(data)
	if cerr := o.close(werr != nil); werr == nil {
		werr = cerr
	}
	return werr
}

func newScanCommand() *cobra.Command {
	var f analysisFlags
	var out, format, fail string
	var noColor bool
	cmd := &cobra.Command{
		Use:   "scan <snapshot>",
		Short: "Report findings as text, JSON or SARIF, with exit codes for CI",
		Long: "Scan a snapshot (or an analysis.json) and report findings.\n\n" +
			"Exit codes: 0 no unsuppressed finding at or above --fail-on, 1 such findings exist,\n" +
			"2 usage or runtime error.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fm, err := report.ParseFormat(format, report.ScanFormats)
			if err != nil {
				return err
			}
			l, err := f.load(cmd, args[0])
			if err != nil {
				return err
			}
			threshold, gate, err := failOn(fail, l.config, "high")
			if err != nil {
				return err
			}
			if err := f.finish(l); err != nil {
				return err
			}
			toStdout := out == "" || out == "-"
			opts := report.Options{Color: !noColor && colorAllowed() && toStdout && isTerminal(cmd.OutOrStdout())}
			if fm == report.SARIF && l.source != "-" {
				opts.SnapshotURI = sarifURI(l.source)
				if l.redactor != nil {
					opts.SnapshotURI = l.redactor.File(opts.SnapshotURI)
				}
			}
			if err := render(cmd, out, l.analysis, fm, opts); err != nil {
				return err
			}
			if !toStdout {
				f.note(cmd, summaryLine(l.analysis))
			}
			if gate && exceeds(l.analysis.Findings, threshold) {
				return &CodeError{Code: ExitFindings}
			}
			return nil
		},
	}
	f.register(cmd)
	fl := cmd.Flags()
	fl.StringVarP(&format, "format", "f", "text", "output format: text, json, sarif")
	fl.StringVarP(&out, "output", "o", "", "write to a file (mode 0600) instead of stdout")
	fl.StringVar(&fail, "fail-on", "", `exit 1 when an unsuppressed finding is at or above this severity, or "none" (default high)`)
	fl.BoolVar(&noColor, "no-color", false, "disable colors (also NO_COLOR)")
	return cmd
}

func render(cmd *cobra.Command, path string, a *contract.Analysis, fm report.Format, opts report.Options) error {
	o, err := openOutput(cmd, path)
	if err != nil {
		return err
	}
	werr := report.Write(o.w, a, fm, opts)
	if cerr := o.close(werr != nil); werr == nil {
		werr = cerr
	}
	return werr
}

func summaryLine(a *contract.Analysis) string {
	c := report.Counts(a)
	return fmt.Sprintf("%d path(s) to Tier 0; findings: %d critical, %d high, %d medium, %d low, %d info",
		a.Stats.Paths, c["critical"], c["high"], c["medium"], c["low"], c["info"])
}

// sarifURI makes the snapshot path relative to the working directory with
// forward slashes, as code scanning expects repository-relative URIs.
func sarifURI(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		if wd, err := filepath.Abs("."); err == nil {
			if rel, err := filepath.Rel(wd, abs); err == nil && !strings.HasPrefix(rel, "..") {
				path = rel
			}
		}
	}
	return filepath.ToSlash(path)
}

func newDiffCommand() *cobra.Command {
	var f analysisFlags
	var out, format, fail string
	cmd := &cobra.Command{
		Use:   "diff <before> <after>",
		Short: "Show edges, paths and findings added or removed between two snapshots",
		Long: "Compare two snapshots (or unredacted analysis.json files) by stable ID.\n\n" +
			"--format text prints a summary; json prints the scan document of <after> restricted\n" +
			"to added findings; analysis writes <after>'s analysis.json with diff markings for the\n" +
			"UI's Diff view. --fail-on applies to added findings only.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "analysis" {
				return fmt.Errorf("--format: %q (want text, json or analysis)", format)
			}
			redactLater := f.redact
			f.redact = false
			before, err := f.load(cmd, args[0])
			if err != nil {
				return err
			}
			after, err := f.load(cmd, args[1])
			if err != nil {
				return err
			}
			sum, err := diff.Compute(before.analysis, after.analysis)
			if err != nil {
				return err
			}
			threshold, gate, err := failOn(fail, after.config, "high")
			if err != nil {
				return err
			}
			added := map[string]bool{}
			for _, id := range after.analysis.Diff.Added.Findings {
				added[id] = true
			}
			var newFindings []contract.Finding
			for _, fd := range after.analysis.Findings {
				if added[fd.ID] {
					newFindings = append(newFindings, fd)
				}
			}
			f.redact = redactLater
			if err := f.finish(after); err != nil {
				return err
			}
			switch format {
			case "analysis":
				if err := writeAnalysis(cmd, out, after.analysis); err != nil {
					return err
				}
			case "json":
				doc := *after.analysis
				doc.Findings = filterAdded(after.analysis)
				if err := render(cmd, out, &doc, report.JSON, report.Options{}); err != nil {
					return err
				}
			default:
				o, err := openOutput(cmd, out)
				if err != nil {
					return err
				}
				werr := writeDiffText(o.w, after.analysis, sum)
				if cerr := o.close(werr != nil); werr == nil {
					werr = cerr
				}
				if werr != nil {
					return werr
				}
			}
			if gate && exceeds(newFindings, threshold) {
				return &CodeError{Code: ExitFindings}
			}
			return nil
		},
	}
	f.register(cmd)
	fl := cmd.Flags()
	fl.StringVarP(&format, "format", "f", "text", "output format: text, json, analysis")
	fl.StringVarP(&out, "output", "o", "", "write to a file (mode 0600) instead of stdout")
	fl.StringVar(&fail, "fail-on", "", `exit 1 when an added unsuppressed finding is at or above this severity, or "none" (default high)`)
	return cmd
}

// filterAdded returns the findings marked as added (IDs are already
// redacted together with the diff markings when --redact is set).
func filterAdded(a *contract.Analysis) []contract.Finding {
	added := map[string]bool{}
	for _, id := range a.Diff.Added.Findings {
		added[id] = true
	}
	out := []contract.Finding{}
	for _, f := range a.Findings {
		if added[f.ID] {
			out = append(out, f)
		}
	}
	return out
}

func newGraphCommand() *cobra.Command {
	var f analysisFlags
	var out, format, path string
	var pathsOnly bool
	cmd := &cobra.Command{
		Use:   "graph <snapshot|analysis.json>",
		Short: "Export the graph (or one path) as Graphviz DOT or Mermaid",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fm, err := report.ParseFormat(format, report.GraphFormats)
			if err != nil {
				return err
			}
			l, err := f.load(cmd, args[0])
			if err != nil {
				return err
			}
			// Path IDs are given unredacted; map them to their pseudonym.
			if path != "" && f.redact {
				if path, err = pathAfterRedaction(&f, l, path); err != nil {
					return err
				}
			} else if err := f.finish(l); err != nil {
				return err
			}
			return render(cmd, out, l.analysis, fm, report.Options{PathID: path, PathsOnly: pathsOnly})
		},
	}
	f.register(cmd)
	fl := cmd.Flags()
	fl.StringVarP(&format, "format", "f", "dot", "output format: dot, mermaid")
	fl.StringVarP(&out, "output", "o", "", "write to a file (mode 0600) instead of stdout")
	fl.StringVar(&path, "path", "", "draw only this path (p_… ID from scan or analyze)")
	fl.BoolVar(&pathsOnly, "paths-only", false, "draw only nodes and edges on enumerated paths")
	return cmd
}

// pathAfterRedaction redacts the analysis and maps a path ID to its
// pseudonym.
func pathAfterRedaction(f *analysisFlags, l *loaded, path string) (string, error) {
	found := false
	for _, p := range l.analysis.Paths {
		if p.ID == path {
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("unknown path %q", path)
	}
	if err := f.finish(l); err != nil {
		return "", err
	}
	if l.redactor == nil {
		return path, nil // the input was already redacted
	}
	return l.redactor.ID(path), nil
}
