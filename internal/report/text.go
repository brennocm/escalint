package report

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/termsafe"
)

var sevColor = map[string]string{
	"critical": "\x1b[1;31m", "high": "\x1b[31m", "medium": "\x1b[33m", "low": "\x1b[36m", "info": "\x1b[2m",
}

const reset = "\x1b[0m"

// writeText prints findings grouped by source principal, each group with
// the escalation chains that start there, then the fix plan.
func writeText(w io.Writer, a *contract.Analysis, opts Options) error {
	bw := bufio.NewWriter(w)
	ix := newIndex(a)
	sev := func(s string) string {
		tag := strings.ToUpper(s)
		if opts.Color {
			return sevColor[s] + tag + reset
		}
		return tag
	}
	safe := termsafe.Line

	counts := Counts(a)
	var parts []string
	for _, s := range severities {
		if n := counts[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	fmt.Fprintf(bw, "escalint %s: %d account(s), %d node(s), %d edge(s), %d path(s) to Tier 0; %s\n",
		safe(a.Generator.Version), len(a.Snapshot.Accounts), a.Stats.Nodes, a.Stats.Edges, a.Stats.Paths, summary)
	if a.Snapshot.Redacted {
		fmt.Fprintln(bw, "identifiers are redacted (pseudonyms are stable within this run only)")
	}
	for _, n := range a.Notes {
		fmt.Fprintf(bw, "note: %s\n", safe(n))
	}

	// Group findings by subject node; order groups by worst severity.
	groups := map[string][]contract.Finding{}
	var suppressed []contract.Finding
	for _, f := range a.Findings {
		if f.Suppressed != nil {
			suppressed = append(suppressed, f)
			continue
		}
		key := ""
		if f.NodeID != nil {
			key = *f.NodeID
		}
		groups[key] = append(groups[key], f)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank(groups[keys[i]][0].Severity), rank(groups[keys[j]][0].Severity)
		switch {
		case (keys[i] == "") != (keys[j] == ""):
			return keys[j] == "" // findings without a subject last
		case ri != rj:
			return ri < rj
		default:
			return ix.label(keys[i]) < ix.label(keys[j])
		}
	})
	pathsFrom := map[string][]contract.Path{}
	for _, p := range a.Paths {
		pathsFrom[p.Source] = append(pathsFrom[p.Source], p)
	}

	for _, k := range keys {
		fmt.Fprintln(bw)
		if k == "" {
			fmt.Fprintln(bw, "Other findings")
		} else {
			n := ix.nodes[k]
			kind, tier := "", ""
			if n != nil {
				kind, tier = n.Kind, fmt.Sprintf(", tier %d", n.Tier)
			}
			fmt.Fprintf(bw, "%s (%s%s)\n", safe(ix.label(k)), kind, tier)
			for _, p := range pathsFrom[k] {
				fmt.Fprintf(bw, "  path %s [%s, %s, %d step(s)]\n", p.ID, sev(p.Severity), p.Status, p.Length)
				for i, eid := range p.Edges {
					e := ix.edges[eid]
					if e == nil {
						continue
					}
					via := e.Kind
					if len(e.RuleIDs) > 0 {
						via += " " + strings.Join(e.RuleIDs, ",")
					}
					fmt.Fprintf(bw, "    %d. %s --[%s]--> %s\n", i+1, safe(ix.label(e.From)), via, safe(ix.label(e.To)))
				}
			}
		}
		for _, f := range groups[k] {
			writeFinding(bw, f, sev, ix)
		}
	}
	if len(a.FixPlan) > 0 {
		fmt.Fprintln(bw)
		fmt.Fprintln(bw, "Fix plan (cuts every enumerated path)")
		for _, s := range a.FixPlan {
			fmt.Fprintf(bw, "  %d. %s (cuts %d path(s))\n", s.Order, safe(s.Change), len(s.PathsCut))
		}
	}
	if len(suppressed) > 0 {
		fmt.Fprintln(bw)
		fmt.Fprintf(bw, "Suppressed (%d)\n", len(suppressed))
		for _, f := range suppressed {
			fmt.Fprintf(bw, "  %s %s %s: %s\n", sev(f.Severity), f.RuleID, f.ID, safe(f.Suppressed.Reason))
		}
	}
	return bw.Flush()
}

func writeFinding(w io.Writer, f contract.Finding, sev func(string) string, ix index) {
	safe := termsafe.Line
	latent := ""
	if f.Latent {
		latent = " (latent)"
	}
	fmt.Fprintf(w, "  %s %s %s%s\n", sev(f.Severity), f.RuleID, safe(f.Title), latent)
	fmt.Fprintf(w, "    %s\n", safe(f.Message))
	if f.Location.Policy != "" {
		at := f.Location.Policy
		if f.Location.StatementIndex >= 0 {
			at += fmt.Sprintf(" statement #%d", f.Location.StatementIndex)
		}
		if f.Location.Path != "" {
			at += " at " + f.Location.Path
		}
		if f.Location.Line != nil {
			at += fmt.Sprintf(" (snapshot line %d)", *f.Location.Line)
		}
		fmt.Fprintf(w, "    policy: %s\n", safe(at))
	}
	if r := ix.rules[f.RuleID]; r != nil && len(r.Attack) > 0 {
		ids := make([]string, 0, len(r.Attack))
		for _, t := range r.Attack {
			ids = append(ids, t.ID+" "+t.Name)
		}
		fmt.Fprintf(w, "    ATT&CK: %s\n", strings.Join(ids, "; "))
	}
	if f.Remediation != "" {
		fmt.Fprintf(w, "    fix: %s\n", safe(f.Remediation))
	}
	fmt.Fprintf(w, "    id: %s\n", f.ID)
}
