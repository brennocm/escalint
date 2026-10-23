// Package engine runs a full analysis: it builds the graph, applies the
// enabled rules in pass order, runs the graph analyses and turns edges and
// rule results into findings and a fix plan. Its output is deterministic;
// reporters and the analysis.json contract are built from it.
package engine

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brennocm/escalint/internal/analysis"
	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/match"
	"github.com/brennocm/escalint/internal/rules"
	"github.com/brennocm/escalint/internal/snapshot"
)

// Options controls a run. The zero value runs every stable rule with the
// default path limits and reports every severity.
type Options struct {
	// Enable adds rules (experimental ones included) by ID or glob
	// ("EL-PE-02?"); Disable removes them and wins over Enable.
	Enable, Disable []string
	// Experimental enables every experimental rule.
	Experimental bool
	// MinSeverity drops findings below it ("" keeps everything).
	MinSeverity rules.Severity
	MaxDepth    int // path and reach depth (default analysis.DefaultMaxDepth)
	K           int // paths per source (default analysis.DefaultK)
	Config      rules.Config
	Now         time.Time // staleness reference, see graph.Options
	Catalog     *catalog.Catalog
}

// Finding is one reported problem.
type Finding struct {
	ID          string
	RuleID      string
	Severity    rules.Severity
	Title       string
	Message     string
	NodeID      string // subject: the edge source for path rules
	EdgeID      string
	PathID      string // shortest enumerated path through the edge, if any
	Latent      bool   // the edge is latent (not usable by paths yet)
	Location    rules.Location
	Remediation string
}

// FixChange is a fix plan step with the concrete change to make.
type FixChange struct {
	Order    int
	EdgeID   string
	Change   string
	Target   string // policy source + "#" + statement index, or ""
	PathsCut []string
}

// Result is everything a reporter needs.
type Result struct {
	Snapshot    *snapshot.Snapshot
	Graph       *graph.Graph
	Env         *graph.Env
	Catalog     *catalog.Catalog
	Rules       []rules.Rule // enabled rules, sorted by ID
	Paths       []analysis.Path
	Cycles      [][]string
	ChokePoints []analysis.ChokePoint
	FixPlan     []FixChange
	Blast       map[string]analysis.Blast // user, role and group nodes
	Findings    []Finding
	Notes       []string
	Options     Options // with defaults applied
}

// ErrUnknownRule is returned when Enable or Disable names no rule.
var ErrUnknownRule = errors.New("unknown rule")

// PathSeverity is the severity of an enumerated path: critical when every
// edge is allowed, high when a condition or prerequisite could not be
// verified.
func PathSeverity(p analysis.Path) rules.Severity {
	if p.Status == graph.StatusAllowed {
		return rules.Critical
	}
	return rules.High
}

// Select returns the rules a run with these options executes.
func Select(opts Options) ([]rules.Rule, error) {
	all := rules.All()
	matches := func(pattern string) ([]rules.Rule, error) {
		var out []rules.Rule
		for _, r := range all {
			if match.Glob(pattern, r.Meta().ID) {
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: %q", ErrUnknownRule, pattern)
		}
		return out, nil
	}
	enabled := map[string]bool{}
	for _, r := range all {
		m := r.Meta()
		enabled[m.ID] = m.Status == rules.Stable || opts.Experimental
	}
	for _, p := range opts.Enable {
		list, err := matches(p)
		if err != nil {
			return nil, err
		}
		for _, r := range list {
			enabled[r.Meta().ID] = true
		}
	}
	for _, p := range opts.Disable {
		list, err := matches(p)
		if err != nil {
			return nil, err
		}
		for _, r := range list {
			enabled[r.Meta().ID] = false
		}
	}
	var out []rules.Rule
	for _, r := range all {
		if enabled[r.Meta().ID] {
			out = append(out, r)
		}
	}
	return out, nil
}

// Run analyzes a snapshot.
func Run(snap *snapshot.Snapshot, opts Options) (*Result, error) {
	selected, err := Select(opts)
	if err != nil {
		return nil, err
	}
	cat := opts.Catalog
	if cat == nil {
		if cat, err = catalog.Default(); err != nil {
			return nil, err
		}
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = analysis.DefaultMaxDepth
	}
	if opts.K <= 0 {
		opts.K = analysis.DefaultK
	}

	g, env := graph.Build(snap, graph.Options{Now: opts.Now})
	byID := map[string]rules.Rule{}
	for _, r := range selected {
		byID[r.Meta().ID] = r
	}
	if byID[graph.RuleAssume] == nil {
		// The builder adds assume edges; without their rule they must not
		// take part in paths or composites.
		drop := map[string]bool{}
		for _, e := range g.Edges() {
			if e.Kind == graph.EdgeAssume {
				drop[e.ID] = true
			}
		}
		g = g.RemoveEdges(drop)
	}

	ctx := &rules.Context{Graph: g, Env: env, Snap: snap, Catalog: cat, Config: opts.Config}
	var direct []rules.Finding
	for _, pass := range []rules.Pass{rules.PassPrimitive, rules.PassComposite} {
		for _, r := range selected {
			if r.Pass() == pass {
				direct = append(direct, r.Apply(ctx)...)
			}
		}
	}

	paths := analysis.Enumerate(g, analysis.PathOptions{K: opts.K, MaxDepth: opts.MaxDepth})
	finder := analysis.NewCapabilityFinder(cat, env)
	var primitives []string
	for _, r := range selected {
		primitives = append(primitives, r.Meta().RequiredActions...)
	}
	analysis.AssignTiers(g, paths, analysis.TierInputs{Finder: finder, Primitives: primitives})

	res := &Result{
		Snapshot: snap, Graph: g, Env: env, Catalog: cat, Rules: selected,
		Paths:       paths,
		Cycles:      analysis.Cycles(g),
		ChokePoints: analysis.ChokePoints(paths),
		Notes:       env.Notes(),
		Options:     opts,
	}
	res.Blast = analysis.BlastAll(g, finder)
	steps := analysis.FixPlan(paths, func(id string) bool {
		e := g.Edge(id)
		return e != nil && e.Kind != graph.EdgeAdmin
	})
	for _, s := range steps {
		change, target := ChangeFor(g, g.Edge(s.EdgeID))
		res.FixPlan = append(res.FixPlan, FixChange{Order: s.Order, EdgeID: s.EdgeID, Change: change, Target: target, PathsCut: s.PathsCut})
	}
	res.Findings = findings(g, paths, byID, direct, opts.MinSeverity)
	return res, nil
}

// findings turns rule edges and direct results into sorted findings.
func findings(g *graph.Graph, paths []analysis.Path, byID map[string]rules.Rule, direct []rules.Finding, minSev rules.Severity) []Finding {
	shortest := map[string]analysis.Path{}
	for _, p := range paths {
		for _, e := range p.Edges {
			cur, ok := shortest[e]
			if !ok || p.Length() < cur.Length() || (p.Length() == cur.Length() && p.ID < cur.ID) {
				shortest[e] = p
			}
		}
	}
	var out []Finding
	for _, e := range g.Edges() {
		for _, id := range e.RuleIDs {
			r := byID[id]
			if r == nil {
				continue
			}
			m := r.Meta()
			f := Finding{
				ID: findingID(id, e.ID), RuleID: id, Severity: m.Severity, Title: m.Title,
				Message: edgeMessage(g, e, ruleActions(e, m)), NodeID: e.From, EdgeID: e.ID, Latent: e.Latent,
				Location: locationOf(g, e), Remediation: m.Remediation,
			}
			if e.Latent && f.Severity.Rank() < rules.High.Rank() {
				// A latent edge needs another step to be used (research §5.10).
				f.Severity = rules.High
			}
			if p, ok := shortest[e.ID]; ok {
				f.PathID = p.ID
				f.Severity = rules.Critical
			}
			out = append(out, f)
		}
	}
	for _, d := range direct {
		f := Finding{
			ID:     findingID(d.RuleID, d.NodeID, d.EdgeID, d.Location.Policy, strconv.Itoa(d.Location.Statement), d.Location.Path, d.Message),
			RuleID: d.RuleID, Severity: d.Severity, Title: d.Title, Message: d.Message,
			NodeID: d.NodeID, EdgeID: d.EdgeID, Location: d.Location,
		}
		if r := byID[d.RuleID]; r != nil {
			f.Remediation = r.Meta().Remediation
			if f.Title == "" {
				f.Title = r.Meta().Title
			}
		}
		if p, ok := shortest[d.EdgeID]; ok && d.EdgeID != "" {
			// A weak trust on a path to Tier 0 lets an outsider become admin.
			f.PathID = p.ID
			f.Severity = rules.Critical
		}
		out = append(out, f)
	}
	if minSev != "" {
		out = slices.DeleteFunc(out, func(f Finding) bool { return f.Severity.Rank() > minSev.Rank() })
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return cmp.Or(
			cmp.Compare(a.Severity.Rank(), b.Severity.Rank()),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.ID, b.ID),
		) < 0
	})
	// Identical direct results (same rule, subject and location) collapse.
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.ID == b.ID })
}

func findingID(parts ...string) string {
	// Finding IDs share the hashing scheme of the graph IDs (ADR 0010).
	return "f_" + strings.TrimPrefix(graph.PathID(parts), "p_")
}

func nodeLabel(g *graph.Graph, id string) string {
	n := g.Node(id)
	switch {
	case n == nil:
		return id
	case n.ARN != "":
		return n.ARN
	case n.Kind == graph.NodeTier0Sink:
		return "effective admin of account " + n.Account
	default:
		return n.Name
	}
}

// ruleActions are the edge's required actions that belong to the rule (an
// edge merges every rule that produced it).
func ruleActions(e *graph.Edge, m rules.Metadata) []string {
	var out []string
	for _, a := range e.RequiredActions {
		if slices.Contains(m.RequiredActions, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return e.RequiredActions
	}
	return out
}

func edgeMessage(g *graph.Graph, e *graph.Edge, actions []string) string {
	actor := ""
	if e.Actor != "" && e.Actor != e.From {
		actor = " (performed by " + nodeLabel(g, e.Actor) + ")"
	}
	verb := "can act as"
	if e.Latent {
		verb = "can modify the permissions of"
	}
	msg := fmt.Sprintf("%s %s %s%s using %s", nodeLabel(g, e.From), verb, nodeLabel(g, e.To), actor, strings.Join(actions, ", "))
	if e.Status == graph.StatusConditional {
		var why []string
		if len(e.ConditionsUnevaluated) > 0 {
			why = append(why, "conditions not evaluated: "+strings.Join(e.ConditionsUnevaluated, ", "))
		}
		if len(e.PrerequisitesUnverified) > 0 {
			why = append(why, "prerequisites not verified: "+strings.Join(e.PrerequisitesUnverified, "; "))
		}
		if len(why) > 0 {
			msg += " (conditional; " + strings.Join(why, "; ") + ")"
		} else {
			msg += " (conditional)"
		}
	}
	return msg
}

// locationOf points at the first identity statement that grants the edge,
// else the first evidence of any stage.
func locationOf(g *graph.Graph, e *graph.Edge) rules.Location {
	loc := rules.Location{Statement: -1}
	ev, ok := primaryEvidence(e)
	if !ok {
		if n := g.Node(e.From); n != nil {
			loc.Account, loc.Entity = n.Account, n.ARN
		}
		return loc
	}
	loc.Policy, loc.Statement = ev.Policy, ev.Statement
	if n := g.Node(ev.Principal); n != nil {
		loc.Account, loc.Entity = n.Account, n.ARN
	}
	return loc
}

func primaryEvidence(e *graph.Edge) (graph.Evidence, bool) {
	if e == nil || len(e.Evidence) == 0 {
		return graph.Evidence{}, false
	}
	for _, ev := range e.Evidence {
		if ev.Stage == "identity" {
			return ev, true
		}
	}
	return e.Evidence[0], true
}

func statementLabel(ev graph.Evidence) string {
	if ev.Sid != "" {
		return "statement Sid=" + ev.Sid
	}
	return "statement #" + strconv.Itoa(ev.Statement)
}

// ChangeFor describes the concrete change that removes an edge, from its
// evidence (ADR 0009).
func ChangeFor(g *graph.Graph, e *graph.Edge) (change, target string) {
	if e == nil {
		return "", ""
	}
	ev, ok := primaryEvidence(e)
	if !ok {
		return fmt.Sprintf("Remove the permissions that let %s act as %s (%s)", nodeLabel(g, e.From), nodeLabel(g, e.To), strings.Join(e.RequiredActions, ", ")), ""
	}
	target = ev.Policy + "#" + strconv.Itoa(ev.Statement)
	var actions []string
	for _, x := range e.Evidence {
		if x.Policy == ev.Policy && x.Statement == ev.Statement && x.Action != "" {
			actions = append(actions, x.Action)
		}
	}
	slices.Sort(actions)
	actions = slices.Compact(actions)
	switch {
	case e.Kind == graph.EdgeAdmin:
		return fmt.Sprintf("Replace the administrator access granted to %s by %s of %s with least-privilege permissions", nodeLabel(g, e.From), statementLabel(ev), ev.Policy), target
	case strings.HasPrefix(ev.Policy, "trust:"):
		return fmt.Sprintf("Restrict %s of the trust policy of %s so it no longer admits %s", statementLabel(ev), nodeLabel(g, e.To), nodeLabel(g, e.From)), target
	case slices.Contains(actions, "iam:PassRole"):
		return fmt.Sprintf("Scope iam:PassRole in %s of %s to the roles that must be passed (exclude %s) and add an iam:PassedToService condition", statementLabel(ev), ev.Policy, nodeLabel(g, e.To)), target
	}
	victim := nodeLabel(g, e.To)
	if n := g.Node(e.To); n != nil && n.Kind == graph.NodeTier0Sink {
		victim = compositeTarget(e)
	}
	if victim == "" {
		return fmt.Sprintf("Remove %s from %s of %s", strings.Join(actions, ", "), statementLabel(ev), ev.Policy), target
	}
	return fmt.Sprintf("Remove %s from %s of %s, or scope its Resource to exclude %s", strings.Join(actions, ", "), statementLabel(ev), ev.Policy, victim), target
}

// compositeTarget names the principal a composite edge modifies, from the
// trust evidence the composite rules record ("trust:<arn>" or
// "rewritten-trust:<arn>").
func compositeTarget(e *graph.Edge) string {
	for _, ev := range e.Evidence {
		for _, prefix := range []string{"trust:", "rewritten-trust:"} {
			if arn, ok := strings.CutPrefix(ev.Policy, prefix); ok {
				return arn
			}
		}
	}
	return ""
}
