package contract

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"
	"sort"
	"time"

	"github.com/brennocm/escalint/internal/analysis"
	"github.com/brennocm/escalint/internal/attack"
	"github.com/brennocm/escalint/internal/buildinfo"
	"github.com/brennocm/escalint/internal/detect"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/eval"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/rules"
	"github.com/brennocm/escalint/internal/snapshot"
)

// Meta is what the contract needs beyond the engine result.
type Meta struct {
	// Duration is reported in stats unless Deterministic is set.
	Duration      time.Duration
	Deterministic bool
	Groupings     []Grouping
	// Locator, when the snapshot came from a file, fills location.line.
	Locator *snapshot.Locator
}

// Build converts an engine result into the contract document.
func Build(res *engine.Result, meta Meta) (*Analysis, error) {
	att, err := attack.Default()
	if err != nil {
		return nil, err
	}
	det, err := detect.Default()
	if err != nil {
		return nil, err
	}
	a := &Analysis{
		SchemaVersion: SchemaVersion,
		Generator:     Generator{Name: "escalint", Version: buildinfo.Version, Commit: buildinfo.Commit},
		Catalogs: Catalogs{
			ServiceReference: res.Catalog.Generated,
			Pathfinding:      rules.PathfindingCommit(),
			Attack:           att.Version,
		},
		Options: RunOptions{
			MaxDepth: res.Options.MaxDepth, KPaths: res.Options.K,
			Experimental: res.Options.Experimental, MinSeverity: string(res.Options.MinSeverity),
		},
		Suppressions: []Suppression{},
		Notes:        list(res.Notes),
		Groupings:    list(meta.Groupings),
	}
	a.Snapshot = snapshotInfo(res)

	techniques := map[string][]string{} // rule ID -> technique IDs
	for _, r := range res.Rules {
		m := r.Meta()
		a.Options.EnabledRules = append(a.Options.EnabledRules, m.ID)
		a.Rules = append(a.Rules, ruleOf(m, att))
		techniques[m.ID] = m.Attack
	}
	a.Options.EnabledRules = list(a.Options.EnabledRules)
	a.Rules = list(a.Rules)

	for _, n := range res.Graph.Nodes() {
		a.Nodes = append(a.Nodes, nodeOf(n, res.Blast))
	}
	edgeAttack := map[string][]string{}
	for _, e := range res.Graph.Edges() {
		var ids []string
		for _, r := range e.RuleIDs {
			ids = append(ids, techniques[r]...)
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		edgeAttack[e.ID] = ids
		a.Edges = append(a.Edges, edgeOf(e, ids, det))
	}
	for _, p := range res.Paths {
		a.Paths = append(a.Paths, Path{
			ID: p.ID, Source: p.Source, Target: p.Target, Edges: list(p.Edges), Nodes: list(p.Nodes),
			Length: p.Length(), Status: string(p.Status), Severity: string(engine.PathSeverity(p)),
		})
	}
	for _, f := range res.Findings {
		cf := FindingOf(f)
		if meta.Locator != nil {
			if line, ok := meta.Locator.Find(f.Location.Entity, f.Location.Policy, f.Location.Statement); ok {
				cf.Location.Line = &line
			}
		}
		a.Findings = append(a.Findings, cf)
	}
	for _, c := range res.ChokePoints {
		a.ChokePoints = append(a.ChokePoints, ChokePoint{EdgeID: c.EdgeID, PathsCut: c.PathsCut, Share: c.Share})
	}
	for _, c := range res.Cycles {
		a.Cycles = append(a.Cycles, list(c))
	}
	for _, s := range res.FixPlan {
		a.FixPlan = append(a.FixPlan, FixStep{Order: s.Order, EdgeID: s.EdgeID, Change: s.Change, Target: s.Target, PathsCut: list(s.PathsCut)})
	}
	a.Nodes, a.Edges, a.Paths, a.Findings = list(a.Nodes), list(a.Edges), list(a.Paths), list(a.Findings)
	a.ChokePoints, a.Cycles, a.FixPlan = list(a.ChokePoints), list(a.Cycles), list(a.FixPlan)
	a.Attack = coverage(att.Version, a.Findings, techniques, res.Paths, edgeAttack)
	if a.Policies, err = citedPolicies(res); err != nil {
		return nil, err
	}
	a.Stats = Stats{Nodes: len(a.Nodes), Edges: len(a.Edges), Paths: len(a.Paths), Findings: len(a.Findings)}
	if !meta.Deterministic {
		ms := meta.Duration.Milliseconds()
		a.Stats.DurationMS = &ms
	}
	return a, nil
}

// citedPolicies collects the documents of every policy named by evidence.
func citedPolicies(res *engine.Result) ([]PolicyDoc, error) {
	cited := map[string]bool{}
	for _, e := range res.Graph.Edges() {
		for _, ev := range e.Evidence {
			cited[ev.Policy] = true
		}
	}
	found := map[string]PolicyDoc{}
	add := func(p *eval.Policy, kind string) error {
		if p == nil || p.Doc == nil || !cited[p.Source] {
			return nil
		}
		if _, ok := found[p.Source]; ok {
			return nil
		}
		doc, err := p.Doc.CanonicalJSON()
		if err != nil {
			return err
		}
		found[p.Source] = PolicyDoc{Source: p.Source, Name: p.Name, Type: kind, Document: doc}
		return nil
	}
	for _, n := range res.Graph.Nodes() {
		if pr := res.Env.Principal(n.ID); pr != nil {
			for i := range pr.Identity {
				if err := add(&pr.Identity[i], "identity"); err != nil {
					return nil, err
				}
			}
			if err := add(pr.Boundary, "boundary"); err != nil {
				return nil, err
			}
		}
		if err := add(res.Env.TrustPolicy(n.ID), "trust"); err != nil {
			return nil, err
		}
	}
	out := make([]PolicyDoc, 0, len(found))
	for _, p := range found {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

func snapshotInfo(res *engine.Result) SnapshotInfo {
	s := SnapshotInfo{Format: string(res.Snapshot.Format), Partition: res.Snapshot.Partition, Accounts: []string{}}
	if !res.Snapshot.CollectedAt.IsZero() {
		s.CollectedAt = ptr(res.Snapshot.CollectedAt.UTC().Format(time.RFC3339))
	}
	for _, acct := range res.Snapshot.Accounts {
		s.Accounts = append(s.Accounts, acct.ID)
	}
	if res.Env.OrgID != "" {
		s.Organization = ptr(res.Env.OrgID)
	}
	return s
}

func ruleOf(m rules.Metadata, att *attack.Data) Rule {
	r := Rule{
		ID: m.ID, Title: m.Title, Category: string(m.Category), Severity: string(m.Severity), Status: string(m.Status),
		PathfindingIDs: list(m.PathfindingIDs), RequiredActions: list(m.RequiredActions), Prerequisites: list(m.Prerequisites),
		Remediation: m.Remediation, References: list(m.References), Attack: []Technique{},
	}
	if m.EdgeKind != "" {
		r.EdgeKind = ptr(string(m.EdgeKind))
	}
	if m.AttackUnmappedReason != "" {
		r.AttackUnmappedReason = ptr(m.AttackUnmappedReason)
	}
	for _, t := range m.AttackRefs(att) {
		r.Attack = append(r.Attack, Technique{ID: t.TechniqueID, Name: t.Name, Tactics: list(t.Tactics), URL: t.URL})
	}
	return r
}

func nodeOf(n *graph.Node, blast map[string]analysis.Blast) Node {
	out := Node{
		ID: n.ID, Kind: string(n.Kind), Name: n.Name, Account: n.Account, Tags: map[string]string{},
		Tier: n.Tier, TierConditional: n.TierConditional, Flags: list(n.Flags),
		ServiceLinked: slices.Contains(n.Flags, "service_linked"),
	}
	if n.ARN != "" {
		out.ARN = ptr(n.ARN)
	}
	if n.Path != "" {
		out.Path = ptr(n.Path)
	}
	for k, v := range n.Tags {
		out.Tags[k] = v
	}
	if n.LastUsed != nil {
		out.LastUsed = ptr(n.LastUsed.UTC().Format(time.RFC3339))
	}
	if b, ok := blast[n.ID]; ok {
		caps := Capabilities{
			PermissionManagement: list(b.Capabilities[analysis.ClassPermissionManagement]),
			Write:                list(b.Capabilities[analysis.ClassWrite]),
			Read:                 list(b.Capabilities[analysis.ClassRead]),
			List:                 list(b.Capabilities[analysis.ClassList]),
		}
		out.Blast = &Blast{ReachablePrincipals: b.ReachablePrincipals, ReachesTier0: b.ReachesTier0, Capabilities: caps}
	}
	return out
}

func edgeOf(e *graph.Edge, techniques []string, det *detect.Catalog) Edge {
	out := Edge{
		ID: e.ID, From: e.From, To: e.To, Kind: string(e.Kind), Status: string(e.Status),
		RuleIDs: list(e.RuleIDs), PathfindingIDs: list(e.PathfindingIDs), RequiredActions: list(e.RequiredActions),
		ConditionsUnevaluated: list(e.ConditionsUnevaluated), PrerequisitesUnverified: list(e.PrerequisitesUnverified),
		Latent: e.Latent, Attack: list(techniques), Evidence: []Evidence{},
	}
	if e.Actor != "" {
		out.Actor = ptr(e.Actor)
	}
	for _, ev := range e.Evidence {
		out.Evidence = append(out.Evidence, Evidence{
			Principal: ev.Principal, Action: ev.Action, Policy: ev.Policy, StatementIndex: ev.Statement,
			Sid: ev.Sid, Effect: ev.Effect, Stage: ev.Stage,
		})
	}
	step := det.ForStep(string(e.Kind), e.RequiredActions)
	out.Detection = Detection{
		BlindSpots: list(step.BlindSpots), RequiresDataEvents: step.RequiresDataEvents,
		Status: string(step.Status), Visibility: string(step.Visibility), Events: []Event{},
	}
	for _, ev := range step.Events {
		out.Detection.Events = append(out.Detection.Events, Event{
			Source: ev.Source, Name: ev.Name, Kind: string(ev.Kind), KeyFields: list(ev.KeyFields), Region: ev.Region, Notes: ev.Notes,
		})
	}
	return out
}

// FindingOf converts an engine finding.
func FindingOf(f engine.Finding) Finding {
	out := Finding{
		ID: f.ID, RuleID: f.RuleID, Severity: string(f.Severity), Title: f.Title, Message: f.Message,
		Latent: f.Latent, Remediation: f.Remediation,
		Location: Location{
			Account: f.Location.Account, Entity: f.Location.Entity, Policy: f.Location.Policy,
			StatementIndex: f.Location.Statement, Path: f.Location.Path,
		},
	}
	if f.NodeID != "" {
		out.NodeID = ptr(f.NodeID)
	}
	if f.EdgeID != "" {
		out.EdgeID = ptr(f.EdgeID)
	}
	if f.PathID != "" {
		out.PathID = ptr(f.PathID)
	}
	return out
}

func coverage(version string, findings []Finding, techniques map[string][]string, paths []analysis.Path, edgeAttack map[string][]string) AttackCoverage {
	findingCount, pathCount := map[string]int{}, map[string]int{}
	for _, f := range findings {
		for _, t := range techniques[f.RuleID] {
			findingCount[t]++
		}
	}
	for _, p := range paths {
		seen := map[string]bool{}
		for _, e := range p.Edges {
			for _, t := range edgeAttack[e] {
				if !seen[t] {
					seen[t] = true
					pathCount[t]++
				}
			}
		}
	}
	ids := make([]string, 0, len(findingCount))
	for t := range findingCount {
		ids = append(ids, t)
	}
	for t := range pathCount {
		if _, ok := findingCount[t]; !ok {
			ids = append(ids, t)
		}
	}
	sort.Strings(ids)
	out := AttackCoverage{Version: version, Techniques: []TechniqueCount{}}
	for _, t := range ids {
		out.Techniques = append(out.Techniques, TechniqueCount{ID: t, Findings: findingCount[t], Paths: pathCount[t]})
	}
	return out
}

// Marshal encodes the document deterministically: two-space indentation,
// sorted map keys, HTML-sensitive characters escaped (so the document can
// be embedded in the HTML report), and a final newline.
func Marshal(a *Analysis) ([]byte, error) {
	// Indenting while encoding, instead of json.Encoder's encode-then-indent,
	// halves the peak memory on large accounts. The v1 options keep the
	// output byte-identical, including the escaping of '<', '>' and '&'.
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf, jsontext.WithIndent("  "))
	if err := jsonv2.MarshalEncode(enc, a, json.DefaultOptionsV1()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func list[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func ptr[T any](v T) *T { return &v }
