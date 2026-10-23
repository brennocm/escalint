// Package report renders an analysis (already redacted when --redact is
// set) as text, JSON, SARIF 2.1.0, Graphviz DOT or Mermaid. Every renderer
// reads only the contract document, so redaction applies to all of them
// alike, and output is deterministic.
package report

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/rules"
)

// Format is an output format.
type Format string

// Formats.
const (
	Text    Format = "text"
	JSON    Format = "json"
	SARIF   Format = "sarif"
	DOT     Format = "dot"
	Mermaid Format = "mermaid"
)

// Formats lists the formats of `scan` and `graph`.
var (
	ScanFormats  = []Format{Text, JSON, SARIF}
	GraphFormats = []Format{DOT, Mermaid}
)

// ErrFormat is returned for an unknown format.
var ErrFormat = errors.New("unknown format")

// Options controls rendering.
type Options struct {
	Color bool // ANSI colors in text output
	// SnapshotURI is the snapshot location for SARIF physical locations
	// (relative to the repository root when possible); "" omits them.
	SnapshotURI string
	// PathID limits graph output to one path; PathsOnly to the nodes and
	// edges of enumerated paths.
	PathID    string
	PathsOnly bool
}

// Write renders a in the given format.
func Write(w io.Writer, a *contract.Analysis, f Format, opts Options) error {
	switch f {
	case Text:
		return writeText(w, a, opts)
	case JSON:
		return writeJSON(w, a)
	case SARIF:
		return writeSARIF(w, a, opts)
	case DOT:
		return writeDOT(w, a, opts)
	case Mermaid:
		return writeMermaid(w, a, opts)
	}
	return fmt.Errorf("%w %q", ErrFormat, f)
}

// ParseFormat validates a format name against a list.
func ParseFormat(s string, allowed []Format) (Format, error) {
	for _, f := range allowed {
		if string(f) == s {
			return f, nil
		}
	}
	names := make([]string, len(allowed))
	for i, f := range allowed {
		names[i] = string(f)
	}
	return "", fmt.Errorf("%w %q (want one of %s)", ErrFormat, s, strings.Join(names, ", "))
}

// Counts returns the number of unsuppressed findings per severity.
func Counts(a *contract.Analysis) map[string]int {
	out := map[string]int{}
	for _, f := range a.Findings {
		if f.Suppressed == nil {
			out[f.Severity]++
		}
	}
	return out
}

// severities in display order.
var severities = []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low, rules.Info}

func rank(s string) int {
	sev, _ := rules.ParseSeverity(s)
	return sev.Rank()
}

type index struct {
	nodes map[string]*contract.Node
	edges map[string]*contract.Edge
	paths map[string]*contract.Path
	rules map[string]*contract.Rule
}

func newIndex(a *contract.Analysis) index {
	ix := index{nodes: map[string]*contract.Node{}, edges: map[string]*contract.Edge{}, paths: map[string]*contract.Path{}, rules: map[string]*contract.Rule{}}
	for i := range a.Nodes {
		ix.nodes[a.Nodes[i].ID] = &a.Nodes[i]
	}
	for i := range a.Edges {
		ix.edges[a.Edges[i].ID] = &a.Edges[i]
	}
	for i := range a.Paths {
		ix.paths[a.Paths[i].ID] = &a.Paths[i]
	}
	for i := range a.Rules {
		ix.rules[a.Rules[i].ID] = &a.Rules[i]
	}
	return ix
}

// label is the display name of a node: its ARN, else its name.
func (ix index) label(id string) string {
	n := ix.nodes[id]
	switch {
	case n == nil:
		return id
	case n.Kind == "tier0_sink":
		return "effective admin (" + n.Account + ")"
	case n.ARN != nil:
		return *n.ARN
	default:
		return n.Name
	}
}

// short is a compact node name for graphs: kind/name.
func (ix index) short(id string) string {
	n := ix.nodes[id]
	switch {
	case n == nil:
		return id
	case n.Kind == "tier0_sink":
		return "effective admin " + n.Account
	case n.Kind == "user" || n.Kind == "role" || n.Kind == "group":
		return n.Kind + "/" + n.Name
	default:
		return n.Name
	}
}

// subgraph selects the nodes and edges to draw.
func (ix index) subgraph(a *contract.Analysis, opts Options) (nodes []string, edges []string, err error) {
	keepN, keepE := map[string]bool{}, map[string]bool{}
	switch {
	case opts.PathID != "":
		p := ix.paths[opts.PathID]
		if p == nil {
			return nil, nil, fmt.Errorf("unknown path %q", opts.PathID)
		}
		for _, n := range p.Nodes {
			keepN[n] = true
		}
		for _, e := range p.Edges {
			keepE[e] = true
		}
	case opts.PathsOnly:
		for _, p := range a.Paths {
			for _, n := range p.Nodes {
				keepN[n] = true
			}
			for _, e := range p.Edges {
				keepE[e] = true
			}
		}
	default:
		for _, n := range a.Nodes {
			keepN[n.ID] = true
		}
		for _, e := range a.Edges {
			keepE[e.ID] = true
		}
	}
	for id := range keepN {
		nodes = append(nodes, id)
	}
	for id := range keepE {
		edges = append(edges, id)
	}
	sort.Strings(nodes)
	sort.Strings(edges)
	return nodes, edges, nil
}
