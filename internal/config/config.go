// Package config reads .escalint.yaml: trusted and third-party accounts,
// suppressions with mandatory justification, UI groupings and default
// options. The file is decoded strictly (unknown keys are errors) and YAML
// anchors and aliases are rejected, so a hostile file cannot expand into
// gigabytes.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/escalint/internal/arn"
	"github.com/brennocm/escalint/internal/rules"
)

// MaxSize bounds the configuration file.
const MaxSize = 1 << 20

// DefaultName is the file looked up in the working directory.
const DefaultName = ".escalint.yaml"

// File is the decoded configuration.
type File struct {
	Version            int           `yaml:"version"`
	TrustedAccounts    []string      `yaml:"trusted_accounts"`
	ThirdPartyAccounts []string      `yaml:"third_party_accounts"`
	Suppressions       []Suppression `yaml:"suppressions"`
	Groupings          []Grouping    `yaml:"groupings"`
	Rules              RuleOptions   `yaml:"rules"`
	FailOn             string        `yaml:"fail_on"`
	MinSeverity        string        `yaml:"min_severity"`
	// Source is the path the file was read from.
	Source string `yaml:"-"`
}

// Suppression hides the findings of one rule on matching principals.
type Suppression struct {
	Rule    string `yaml:"rule"`    // rule ID or glob ("EL-TR-*")
	ARN     string `yaml:"arn"`     // glob on the finding's subject ARN
	Reason  string `yaml:"reason"`  // required
	Expires string `yaml:"expires"` // optional, YYYY-MM-DD (inclusive)
}

// Grouping names a set of principals for the UI.
type Grouping struct {
	Name string   `yaml:"name"`
	ARNs []string `yaml:"arns"` // globs
}

// RuleOptions are default rule selections (command-line flags add to them).
type RuleOptions struct {
	Enable       []string `yaml:"enable"`
	Disable      []string `yaml:"disable"`
	Experimental bool     `yaml:"experimental"`
}

// ErrInvalid wraps every validation error.
var ErrInvalid = errors.New("invalid configuration")

// RulesConfig returns what rules read.
func (f *File) RulesConfig() rules.Config {
	if f == nil {
		return rules.Config{}
	}
	return rules.Config{TrustedAccounts: f.TrustedAccounts, ThirdPartyAccounts: f.ThirdPartyAccounts}
}

// Load reads a configuration file.
func Load(path string) (*File, error) {
	fh, err := os.Open(path) // #nosec G304 -- the user chose the file
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	f, err := Decode(fh)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.Source = path
	return f, nil
}

// Decode parses and validates a configuration.
func Decode(r io.Reader) (*File, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxSize)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := noAliases(&root); err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func noAliases(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("%w: line %d: YAML anchors and aliases are not allowed", ErrInvalid, n.Line)
	}
	for _, c := range n.Content {
		if err := noAliases(c); err != nil {
			return err
		}
	}
	return nil
}

var rulePattern = regexp.MustCompile(`^EL-[A-Z*?]+(-[0-9*?]+)?$|^\*$`)

func (f *File) validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	if f.Version != 1 {
		return bad("version must be 1, got %d", f.Version)
	}
	for _, list := range []struct {
		name string
		ids  []string
	}{{"trusted_accounts", f.TrustedAccounts}, {"third_party_accounts", f.ThirdPartyAccounts}} {
		for i, id := range list.ids {
			if !arn.IsAccountID(id) {
				return bad("%s[%d]: %q is not a 12-digit account ID", list.name, i, id)
			}
		}
	}
	for i, s := range f.Suppressions {
		if !rulePattern.MatchString(s.Rule) {
			return bad("suppressions[%d].rule: %q is not a rule ID or pattern", i, s.Rule)
		}
		if s.ARN == "" {
			return bad("suppressions[%d].arn is required (use \"*\" for every principal)", i)
		}
		if s.Expires != "" {
			if _, err := time.Parse(time.DateOnly, s.Expires); err != nil {
				return bad("suppressions[%d].expires: %q is not a YYYY-MM-DD date", i, s.Expires)
			}
		}
	}
	for i, g := range f.Groupings {
		if g.Name == "" || len(g.ARNs) == 0 {
			return bad("groupings[%d] needs a name and at least one ARN pattern", i)
		}
	}
	for _, s := range []struct{ name, value string }{{"fail_on", f.FailOn}, {"min_severity", f.MinSeverity}} {
		if s.value == "" || s.value == "none" && s.name == "fail_on" {
			continue
		}
		if _, ok := rules.ParseSeverity(s.value); !ok {
			return bad("%s: %q is not a severity", s.name, s.value)
		}
	}
	return nil
}

// Expired reports whether a suppression has expired at now (the expiry day
// itself is still valid).
func (s Suppression) Expired(now time.Time) bool {
	if s.Expires == "" {
		return false
	}
	day, err := time.Parse(time.DateOnly, s.Expires)
	if err != nil {
		return true // validated on load; an unparsable date never suppresses
	}
	return now.UTC().After(day.Add(24*time.Hour - time.Nanosecond))
}
