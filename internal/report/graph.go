package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/brennocm/escalint/internal/contract"
)

var dotShape = map[string]string{
	"user": "ellipse", "role": "box", "group": "folder", "service": "component",
	"external_account": "house", "federated": "cds", "any_principal": "doubleoctagon", "tier0_sink": "doublecircle",
}

// Tier colors match the light theme of the UI design tokens.
var dotTierColor = map[int]string{0: "#b42318", 1: "#c4320a", 2: "#b54708", 3: "#475467"}

// dotQuote escapes a string for a DOT quoted ID: backslashes and quotes
// are escaped and line breaks removed, so untrusted names cannot close the
// string or inject attributes.
func dotQuote(s string) string { return `"` + dotEscape(s) + `"` }

func dotEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ").Replace(s)
}

func writeDOT(w io.Writer, a *contract.Analysis, opts Options) error {
	ix := newIndex(a)
	nodes, edges, err := ix.subgraph(a, opts)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	fmt.Fprintln(bw, "digraph escalint {")
	fmt.Fprintln(bw, `  graph [rankdir=LR, fontname="Helvetica"];`)
	fmt.Fprintln(bw, `  node [fontname="Helvetica", fontsize=10];`)
	fmt.Fprintln(bw, `  edge [fontname="Helvetica", fontsize=9];`)
	for _, id := range nodes {
		n := ix.nodes[id]
		if n == nil {
			continue
		}
		fmt.Fprintf(bw, "  %s [label=%s, shape=%s, color=%s, tooltip=%s];\n",
			dotQuote(id), `"`+dotEscape(ix.short(id))+`\ntier `+fmt.Sprint(n.Tier)+`"`, dotShape[n.Kind],
			dotQuote(dotTierColor[n.Tier]), dotQuote(ix.label(id)))
	}
	for _, id := range edges {
		e := ix.edges[id]
		if e == nil {
			continue
		}
		style := "solid"
		switch {
		case e.Latent:
			style = "dotted"
		case e.Status == "conditional":
			style = "dashed"
		}
		label := e.Kind
		if len(e.RuleIDs) > 0 {
			label += " " + strings.Join(e.RuleIDs, ",")
		}
		fmt.Fprintf(bw, "  %s -> %s [label=%s, style=%s, tooltip=%s];\n",
			dotQuote(e.From), dotQuote(e.To), dotQuote(label), style, dotQuote(strings.Join(e.RequiredActions, ", ")))
	}
	fmt.Fprintln(bw, "}")
	return bw.Flush()
}

// mermaidText escapes a label for Mermaid: characters Mermaid would parse
// or render as HTML become entity codes ('#' first, as entities use it).
func mermaidText(s string) string {
	r := strings.NewReplacer("#", "#35;", `"`, "#quot;", "<", "#lt;", ">", "#gt;", "&", "#amp;",
		"\n", " ", "\r", " ", "`", "#96;", "|", "#124;", "[", "#91;", "]", "#93;", "{", "#123;", "}", "#125;")
	return r.Replace(s)
}

var mermaidShape = map[string][2]string{
	"user": {"([", "])"}, "role": {"[", "]"}, "group": {"[[", "]]"}, "service": {"[/", "/]"},
	"external_account": {"{{", "}}"}, "federated": {"[\\", "\\]"}, "any_principal": {"((", "))"}, "tier0_sink": {"(((", ")))"},
}

func writeMermaid(w io.Writer, a *contract.Analysis, opts Options) error {
	ix := newIndex(a)
	nodes, edges, err := ix.subgraph(a, opts)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	fmt.Fprintln(bw, "flowchart LR")
	for _, id := range nodes {
		n := ix.nodes[id]
		if n == nil {
			continue
		}
		sh := mermaidShape[n.Kind]
		// Node IDs are n_<hex>: always valid Mermaid identifiers.
		fmt.Fprintf(bw, "  %s%s\"%s<br/>tier %d\"%s\n", id, sh[0], mermaidText(ix.short(id)), n.Tier, sh[1])
	}
	for _, id := range edges {
		e := ix.edges[id]
		if e == nil {
			continue
		}
		arrow := "-->"
		switch {
		case e.Latent:
			arrow = "-.->"
		case e.Status == "conditional":
			arrow = "-.->"
		}
		label := e.Kind
		if len(e.RuleIDs) > 0 {
			label += " " + strings.Join(e.RuleIDs, ",")
		}
		fmt.Fprintf(bw, "  %s %s|\"%s\"| %s\n", e.From, arrow, mermaidText(label), e.To)
	}
	for tier, color := range []string{"#b42318", "#c4320a", "#b54708", "#475467"} {
		fmt.Fprintf(bw, "  classDef tier%d stroke:%s,stroke-width:2px\n", tier, color)
	}
	for _, id := range nodes {
		if n := ix.nodes[id]; n != nil {
			fmt.Fprintf(bw, "  class %s tier%d\n", id, n.Tier)
		}
	}
	return bw.Flush()
}
