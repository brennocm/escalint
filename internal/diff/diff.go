// Package diff compares two analyses by stable ID (ADR 0010): which nodes,
// edges, paths and findings were added or removed. It runs on unredacted
// analyses; redaction, when requested, is applied to the result.
package diff

import (
	"errors"
	"sort"

	"github.com/brennocm/escalint/internal/contract"
)

// ErrRedacted is returned when either side is redacted: pseudonyms change
// on every run, so IDs cannot be compared.
var ErrRedacted = errors.New("redacted analyses cannot be compared; diff the unredacted inputs and pass --redact to diff instead")

// Summary counts the changes.
type Summary struct {
	AddedPaths, RemovedPaths       int
	AddedFindings, RemovedFindings int
	AddedEdges, RemovedEdges       int
	// NewCritical counts added unsuppressed critical findings.
	NewCritical int
}

// Compute marks head with what changed since base and returns a summary.
// head.Diff.Removed.Objects keeps the removed objects so the UI can draw
// them.
func Compute(base, head *contract.Analysis) (Summary, error) {
	if base.Snapshot.Redacted || head.Snapshot.Redacted {
		return Summary{}, ErrRedacted
	}
	d := &contract.Diff{
		Base:  contract.DiffBase{CollectedAt: base.Snapshot.CollectedAt, Generator: base.Generator.Version},
		Added: contract.DiffItems{Edges: []string{}, Paths: []string{}, Findings: []string{}, Nodes: []string{}},
		Removed: contract.DiffItems{
			Edges: []string{}, Paths: []string{}, Findings: []string{}, Nodes: []string{},
			Objects: &contract.Removed{Nodes: []contract.Node{}, Edges: []contract.Edge{}, Paths: []contract.Path{}, Findings: []contract.Finding{}},
		},
	}
	var s Summary

	baseNodes, headNodes := ids(base.Nodes, func(n contract.Node) string { return n.ID }), ids(head.Nodes, func(n contract.Node) string { return n.ID })
	d.Added.Nodes = minus(headNodes, baseNodes)
	d.Removed.Nodes = minus(baseNodes, headNodes)
	for _, n := range base.Nodes {
		if !headNodes[n.ID] {
			d.Removed.Objects.Nodes = append(d.Removed.Objects.Nodes, n)
		}
	}

	baseEdges, headEdges := ids(base.Edges, func(e contract.Edge) string { return e.ID }), ids(head.Edges, func(e contract.Edge) string { return e.ID })
	d.Added.Edges = minus(headEdges, baseEdges)
	d.Removed.Edges = minus(baseEdges, headEdges)
	for _, e := range base.Edges {
		if !headEdges[e.ID] {
			d.Removed.Objects.Edges = append(d.Removed.Objects.Edges, e)
		}
	}

	basePaths, headPaths := ids(base.Paths, func(p contract.Path) string { return p.ID }), ids(head.Paths, func(p contract.Path) string { return p.ID })
	d.Added.Paths = minus(headPaths, basePaths)
	d.Removed.Paths = minus(basePaths, headPaths)
	for _, p := range base.Paths {
		if !headPaths[p.ID] {
			d.Removed.Objects.Paths = append(d.Removed.Objects.Paths, p)
		}
	}

	baseFindings, headFindings := ids(base.Findings, func(f contract.Finding) string { return f.ID }), ids(head.Findings, func(f contract.Finding) string { return f.ID })
	d.Added.Findings = minus(headFindings, baseFindings)
	d.Removed.Findings = minus(baseFindings, headFindings)
	for _, f := range base.Findings {
		if !headFindings[f.ID] {
			d.Removed.Objects.Findings = append(d.Removed.Objects.Findings, f)
		}
	}
	added := map[string]bool{}
	for _, id := range d.Added.Findings {
		added[id] = true
	}
	for _, f := range head.Findings {
		if added[f.ID] && f.Severity == "critical" && f.Suppressed == nil {
			s.NewCritical++
		}
	}

	s.AddedPaths, s.RemovedPaths = len(d.Added.Paths), len(d.Removed.Paths)
	s.AddedFindings, s.RemovedFindings = len(d.Added.Findings), len(d.Removed.Findings)
	s.AddedEdges, s.RemovedEdges = len(d.Added.Edges), len(d.Removed.Edges)
	head.Diff = d
	return s, nil
}

func ids[T any](list []T, id func(T) string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, x := range list {
		out[id(x)] = true
	}
	return out
}

func minus(a, b map[string]bool) []string {
	out := []string{}
	for id := range a {
		if !b[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
