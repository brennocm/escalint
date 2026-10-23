package contract

import (
	"fmt"
	"regexp"
)

// Patterns of identifiers and enumerations in analysis.json (the same as in
// schema/analysis.v1.schema.json). A hand-edited document read back by the
// CLI must match them: renderers write IDs, kinds and statuses verbatim into
// Mermaid, DOT and terminal output.
var (
	nodeID  = regexp.MustCompile(`^n_[0-9a-f]{16}$`)
	edgeID  = regexp.MustCompile(`^e_[0-9a-f]{16}$`)
	pathID  = regexp.MustCompile(`^p_[0-9a-f]{16}$`)
	findID  = regexp.MustCompile(`^f_[0-9a-f]{16}$`)
	ruleID  = regexp.MustCompile(`^EL-(PE|TR|PARSE)-[0-9]{3}$`)
	keyword = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

// ValidateIdentifiers checks the identifiers, kinds and statuses of a
// decoded document.
func ValidateIdentifiers(a *Analysis) error {
	check := func(re *regexp.Regexp, what, v string) error {
		if !re.MatchString(v) {
			return fmt.Errorf("analysis.json: invalid %s %q", what, clip(v))
		}
		return nil
	}
	optional := func(re *regexp.Regexp, what string, v *string) error {
		if v == nil {
			return nil
		}
		return check(re, what, *v)
	}
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	nodes := func(list []Node) {
		for i := range list {
			n := &list[i]
			add(check(nodeID, "node id", n.ID))
			add(check(keyword, "node kind", n.Kind))
		}
	}
	edges := func(list []Edge) {
		for i := range list {
			e := &list[i]
			add(check(edgeID, "edge id", e.ID))
			add(check(nodeID, "edge from", e.From))
			add(check(nodeID, "edge to", e.To))
			add(check(keyword, "edge kind", e.Kind))
			add(check(keyword, "edge status", e.Status))
			for _, r := range e.RuleIDs {
				add(check(ruleID, "rule id", r))
			}
		}
	}
	paths := func(list []Path) {
		for i := range list {
			p := &list[i]
			add(check(pathID, "path id", p.ID))
			add(check(nodeID, "path source", p.Source))
			add(check(nodeID, "path target", p.Target))
			add(check(keyword, "path status", p.Status))
			add(check(keyword, "path severity", p.Severity))
			for _, id := range p.Edges {
				add(check(edgeID, "path edge", id))
			}
			for _, id := range p.Nodes {
				add(check(nodeID, "path node", id))
			}
		}
	}
	findings := func(list []Finding) {
		for i := range list {
			f := &list[i]
			add(check(findID, "finding id", f.ID))
			add(check(ruleID, "rule id", f.RuleID))
			add(check(keyword, "finding severity", f.Severity))
			add(optional(nodeID, "finding node", f.NodeID))
			add(optional(edgeID, "finding edge", f.EdgeID))
			add(optional(pathID, "finding path", f.PathID))
		}
	}
	nodes(a.Nodes)
	edges(a.Edges)
	paths(a.Paths)
	findings(a.Findings)
	if a.Diff != nil {
		for _, d := range []*DiffItems{&a.Diff.Added, &a.Diff.Removed} {
			if d.Objects != nil {
				nodes(d.Objects.Nodes)
				edges(d.Objects.Edges)
				paths(d.Objects.Paths)
				findings(d.Objects.Findings)
			}
		}
	}
	if len(errs) > 0 {
		if len(errs) > 1 {
			return fmt.Errorf("%w (and %d more)", errs[0], len(errs)-1)
		}
		return errs[0]
	}
	return nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
