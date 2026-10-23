package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/internal/config"
	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/jsonx"
	"github.com/brennocm/escalint/internal/redact"
	"github.com/brennocm/escalint/internal/rules"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/suppress"
	"github.com/brennocm/escalint/internal/termsafe"
)

// MaxInput bounds snapshot and analysis files read by any command.
const MaxInput = 200 << 20

// analysisFlags are the options shared by every command that analyzes a
// snapshot.
type analysisFlags struct {
	configFile    string
	enable        []string
	disable       []string
	experimental  bool
	minSeverity   string
	maxDepth      int
	kPaths        int
	redact        bool
	deterministic bool
	quiet         bool
	verbose       bool
}

func (f *analysisFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.configFile, "config-file", "", "configuration file (default: .escalint.yaml in the working directory, if present)")
	fl.StringSliceVar(&f.enable, "enable", nil, "enable rules by ID or glob, including experimental ones (repeatable)")
	fl.StringSliceVar(&f.disable, "disable", nil, "disable rules by ID or glob (repeatable; wins over --enable)")
	fl.BoolVar(&f.experimental, "experimental", false, "enable every experimental rule")
	fl.StringVar(&f.minSeverity, "min-severity", "", "drop findings below this severity: critical, high, medium, low, info")
	fl.IntVar(&f.maxDepth, "max-depth", 0, "maximum path length in edges (default 6)")
	fl.IntVar(&f.kPaths, "k-paths", 0, "shortest paths kept per source principal (default 3)")
	fl.BoolVar(&f.redact, "redact", false, "replace account IDs, names, ARNs, tags and IDs with per-run pseudonyms")
	fl.BoolVar(&f.deterministic, "deterministic", false, "omit timings so the output is byte-for-byte reproducible")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "print nothing on stderr except errors")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "print notes and timings on stderr")
}

// loaded is an input ready for reporting.
type loaded struct {
	analysis *contract.Analysis
	config   *config.File
	source   string // input path, "-" for stdin
	redactor *redact.Redactor
}

// loadConfig reads --config-file, or .escalint.yaml when it exists.
func loadConfig(path string) (*config.File, error) {
	if path != "" {
		return config.Load(path)
	}
	if _, err := os.Stat(config.DefaultName); err == nil {
		return config.Load(config.DefaultName)
	}
	return nil, nil //nolint:nilnil // no configuration is a valid state
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if path != "-" {
		fh, err := os.Open(path) // #nosec G304 -- the user chose the file
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		r = fh
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxInput {
		return nil, fmt.Errorf("%s is larger than %d MB", path, MaxInput>>20)
	}
	return data, nil
}

// isAnalysis reports whether a JSON document is an analysis.json (it has
// schema_version and nodes at the top level).
func isAnalysis(data []byte) bool {
	var probe struct {
		SchemaVersion *string          `json:"schema_version"`
		Nodes         *json.RawMessage `json:"nodes"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.SchemaVersion != nil && probe.Nodes != nil
}

// ErrSchemaVersion is returned for analysis.json files of another version.
var ErrSchemaVersion = errors.New("unsupported analysis schema_version")

func decodeAnalysis(data []byte) (*contract.Analysis, error) {
	if err := jsonx.Check(data, 64); err != nil {
		return nil, err
	}
	var a contract.Analysis
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("analysis.json: %w", err)
	}
	if a.SchemaVersion != contract.SchemaVersion {
		return nil, fmt.Errorf("%w %q (this escalint reads %q)", ErrSchemaVersion, a.SchemaVersion, contract.SchemaVersion)
	}
	return &a, nil
}

// now is the reference time for suppression expiry. ESCALINT_NOW (a
// YYYY-MM-DD date) pins it for reproducible tests.
func now() time.Time {
	if v := os.Getenv("ESCALINT_NOW"); v != "" {
		if t, err := time.Parse(time.DateOnly, v); err == nil {
			return t
		}
	}
	return time.Now()
}

// load reads a snapshot (and analyzes it) or an analysis.json, applies the
// configuration's suppressions and groupings, but does not redact: diff
// needs unredacted IDs. Call finish before rendering.
func (f *analysisFlags) load(cmd *cobra.Command, path string) (*loaded, error) {
	cfg, err := loadConfig(f.configFile)
	if err != nil {
		return nil, err
	}
	data, err := readInput(path, cmd.InOrStdin())
	if err != nil {
		return nil, err
	}
	l := &loaded{config: cfg, source: path}
	if isAnalysis(data) {
		if l.analysis, err = decodeAnalysis(data); err != nil {
			return nil, err
		}
		f.debug(cmd, "input is an analysis.json: rule and path options are ignored")
		return l, nil
	}
	start := time.Now()
	snap, err := snapshot.Load(bytes.NewReader(data), snapshot.Options{})
	if err != nil {
		return nil, err
	}
	opts, err := f.engineOptions(cfg)
	if err != nil {
		return nil, err
	}
	res, err := engine.Run(snap, opts)
	if err != nil {
		return nil, err
	}
	loc, err := snapshot.Locate(data)
	if err != nil {
		return nil, err
	}
	l.analysis, err = contract.Build(res, contract.Meta{Duration: time.Since(start), Deterministic: f.deterministic, Locator: loc})
	if err != nil {
		return nil, err
	}
	suppress.Apply(l.analysis, cfg, now())
	suppress.Group(l.analysis, cfg)
	for _, n := range l.analysis.Notes {
		f.note(cmd, n)
	}
	if l.analysis.Stats.DurationMS != nil {
		f.debug(cmd, fmt.Sprintf("analyzed %d nodes and %d edges in %d ms", l.analysis.Stats.Nodes, l.analysis.Stats.Edges, *l.analysis.Stats.DurationMS))
	}
	return l, nil
}

func (f *analysisFlags) engineOptions(cfg *config.File) (engine.Options, error) {
	opts := engine.Options{
		Enable: f.enable, Disable: f.disable, Experimental: f.experimental,
		MaxDepth: f.maxDepth, K: f.kPaths, Config: cfg.RulesConfig(),
	}
	if f.maxDepth < 0 || f.maxDepth > 20 || f.kPaths < 0 || f.kPaths > 50 {
		return opts, errors.New("--max-depth must be 1..20 and --k-paths 1..50")
	}
	minSev := f.minSeverity
	if cfg != nil {
		opts.Enable = append(slices.Clone(cfg.Rules.Enable), f.enable...)
		opts.Disable = append(slices.Clone(cfg.Rules.Disable), f.disable...)
		opts.Experimental = opts.Experimental || cfg.Rules.Experimental
		if minSev == "" {
			minSev = cfg.MinSeverity
		}
	}
	if minSev != "" {
		sev, ok := rules.ParseSeverity(minSev)
		if !ok {
			return opts, fmt.Errorf("--min-severity: %q is not a severity", minSev)
		}
		opts.MinSeverity = sev
	}
	return opts, nil
}

// finish redacts the analysis when requested. Returns the redactor so
// callers can redact other strings (the snapshot path in SARIF).
func (f *analysisFlags) finish(l *loaded) error {
	if !f.redact {
		return nil
	}
	if l.analysis.Snapshot.Redacted {
		return nil
	}
	r, err := redact.New(nil)
	if err != nil {
		return err
	}
	r.Analysis(l.analysis)
	l.redactor = r
	return nil
}

// note prints an informational message on stderr unless --quiet.
func (f *analysisFlags) note(cmd *cobra.Command, msg string) {
	if !f.quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "escalint: %s\n", termsafe.Line(msg))
	}
}

// debug prints a message only with --verbose.
func (f *analysisFlags) debug(cmd *cobra.Command, msg string) {
	if f.verbose && !f.quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "escalint: %s\n", termsafe.Line(msg))
	}
}

// failOn resolves --fail-on against the configuration; "none" disables it.
func failOn(flag string, cfg *config.File, def string) (rules.Severity, bool, error) {
	v := flag
	if v == "" && cfg != nil {
		v = cfg.FailOn
	}
	if v == "" {
		v = def
	}
	if v == "none" {
		return "", false, nil
	}
	sev, ok := rules.ParseSeverity(v)
	if !ok {
		return "", false, fmt.Errorf("--fail-on: %q is not a severity or none", v)
	}
	return sev, true, nil
}

// exceeds reports whether any unsuppressed finding is at or above sev.
func exceeds(findings []contract.Finding, sev rules.Severity) bool {
	for _, f := range findings {
		if f.Suppressed != nil {
			continue
		}
		if s, ok := rules.ParseSeverity(f.Severity); ok && s.Rank() <= sev.Rank() {
			return true
		}
	}
	return false
}

// output opens the destination of a command: stdout for "" or "-", else a
// file written atomically with mode 0600 (reports describe who can become
// administrator).
type output struct {
	w     io.Writer
	tmp   *os.File
	final string
}

func openOutput(cmd *cobra.Command, path string) (*output, error) {
	if path == "" || path == "-" {
		return &output{w: cmd.OutOrStdout()}, nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".escalint-*")
	if err != nil {
		return nil, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		// Best-effort cleanup of the temporary file; the chmod error is returned.
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return &output{w: tmp, tmp: tmp, final: path}, nil
}

// close commits the file; on error it removes the temporary file.
func (o *output) close(failed bool) error {
	if o.tmp == nil {
		return nil
	}
	name := o.tmp.Name()
	if err := o.tmp.Close(); err != nil || failed {
		_ = os.Remove(name) // best effort: the write or close error is what matters
		return err
	}
	if err := os.Rename(name, o.final); err != nil {
		_ = os.Remove(name) // best effort: report the rename error
		return err
	}
	return nil
}

// isTerminal reports whether w is a character device (a terminal).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
