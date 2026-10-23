// Package redact pseudonymizes an analysis before it leaves the process
// (--redact). Account IDs, principal and policy names, ARNs, paths, tags,
// statement IDs, organization IDs and every graph ID are replaced by
// pseudonyms derived with HMAC-SHA-256 under a key that is random per run,
// so the same identifier gets the same pseudonym within a run (the graph
// stays consistent) and nobody can confirm a guessed ARN by hashing it
// (ADR 0010).
//
// Free text (finding messages, fix plan changes, notes) is rewritten by
// replacing every identifier seen in the structured fields, at identifier
// boundaries, plus any standalone 12-digit number.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/rules"
)

// Redactor holds the run key and the identifiers replaced so far.
type Redactor struct {
	key   []byte
	seen  map[string]string // original -> pseudonym, for free text
	index map[byte][]string // first byte -> originals, longest first
	dirty bool
}

// New returns a redactor. A nil key draws a random 32-byte key; tests pass
// a fixed key for golden files.
func New(key []byte) (*Redactor, error) {
	if key == nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("redact: random key: %w", err)
		}
	}
	return &Redactor{key: key, seen: map[string]string{}}, nil
}

func (r *Redactor) mac(kind, s string) []byte {
	h := hmac.New(sha256.New, r.key)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(s))
	return h.Sum(nil)
}

func (r *Redactor) token(kind, s string, n int) string {
	return hex.EncodeToString(r.mac(kind, s))[:n]
}

func (r *Redactor) remember(orig, pseudo string) string {
	if orig != "" && orig != pseudo {
		if _, ok := r.seen[orig]; !ok {
			r.seen[orig] = pseudo
			r.dirty = true
		}
	}
	return pseudo
}

// Account pseudonymizes a 12-digit account ID into another 12-digit
// number, so ARNs keep their shape. "aws" (AWS managed policies) and ""
// are kept.
func (r *Redactor) Account(id string) string {
	if id == "" || id == "aws" {
		return id
	}
	if p, ok := r.seen[id]; ok {
		return p
	}
	n := binary.BigEndian.Uint64(r.mac("account", id)) % 1_000_000_000_000
	return r.remember(id, fmt.Sprintf("%012d", n))
}

// ID pseudonymizes a graph ID, keeping its prefix (n_, e_, p_, f_).
func (r *Redactor) ID(id string) string {
	if id == "" {
		return id
	}
	prefix, _, ok := strings.Cut(id, "_")
	if !ok {
		prefix = "x"
	}
	return r.remember(id, prefix+"_"+r.token("id", id, 16))
}

// Name pseudonymizes an entity name with a readable kind prefix.
func (r *Redactor) Name(kind, name string) string {
	if name == "" {
		return name
	}
	return r.remember(name, kind+"-"+r.token("name", name, 8))
}

// Path pseudonymizes an IAM path; "/" is kept.
func (r *Redactor) Path(p string) string {
	if p == "" || p == "/" {
		return p
	}
	return r.remember(p, "/path-"+r.token("path", p, 8)+"/")
}

// publicHosts are identity providers whose names are public knowledge and
// that rules refer to (EL-TR-002/003 name GitHub Actions).
var publicHosts = map[string]bool{
	"token.actions.githubusercontent.com": true,
	"accounts.google.com":                 true,
	"cognito-identity.amazonaws.com":      true,
	"graph.facebook.com":                  true,
	"www.amazon.com":                      true,
}

// resourceKinds maps the IAM resource type of an ARN to a name prefix.
var resourceKinds = map[string]string{
	"user": "user", "role": "role", "group": "group", "policy": "policy",
	"instance-profile": "profile", "oidc-provider": "oidc", "saml-provider": "saml",
	"assumed-role": "role", "federated-user": "user",
}

// ARN pseudonymizes an ARN: the account and the resource part (except its
// type) are replaced. AWS managed policies (account "aws") are public and
// kept. Strings that are not ARNs are treated as names.
func (r *Redactor) ARN(s string) string {
	if s == "" || s == "*" {
		return s
	}
	if p, ok := r.seen[s]; ok {
		return p
	}
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return r.Name("id", s)
	}
	if parts[4] == "aws" {
		return s
	}
	parts[4] = r.Account(parts[4])
	resource := parts[5]
	typ, rest, found := strings.Cut(resource, "/")
	switch {
	case !found:
		if resource != "root" {
			parts[5] = "resource-" + r.token("resource", resource, 8)
		}
	case parts[2] == "iam" && resourceKinds[typ] != "":
		if publicHosts[rest] {
			break
		}
		path, name := "/", rest
		if i := strings.LastIndex(rest, "/"); i >= 0 {
			path, name = "/"+rest[:i+1], rest[i+1:]
		}
		parts[5] = typ + r.Path(path) + r.Name(resourceKinds[typ], name)
	default:
		// Outside IAM the first segment is not always a type (S3 buckets).
		parts[5] = "resource-" + r.token("resource", resource, 8)
	}
	return r.remember(s, strings.Join(parts, ":"))
}

// PolicySource pseudonymizes an evidence policy reference: a managed policy
// ARN, "inline:<owner ARN>/<name>", "trust:<role ARN>",
// "rewritten-trust:<role ARN>" or an organization policy ID.
func (r *Redactor) PolicySource(s string) string {
	if s == "" {
		return s
	}
	if p, ok := r.seen[s]; ok {
		return p
	}
	for _, prefix := range []string{"trust:", "rewritten-trust:"} {
		if arn, ok := strings.CutPrefix(s, prefix); ok {
			return r.remember(s, prefix+r.ARN(arn))
		}
	}
	if rest, ok := strings.CutPrefix(s, "inline:"); ok {
		i := strings.LastIndex(rest, "/")
		if i < 0 {
			return r.remember(s, "inline:"+r.Name("inline", rest))
		}
		return r.remember(s, "inline:"+r.ARN(rest[:i])+"/"+r.Name("inline", rest[i+1:]))
	}
	if strings.HasPrefix(s, "arn:") {
		return r.ARN(s)
	}
	return r.Name("policy", s)
}

// Text rewrites free text: every identifier replaced so far, matched at
// identifier boundaries (longest first), and any standalone 12-digit
// number.
func (r *Redactor) Text(s string) string {
	if s == "" {
		return s
	}
	r.reindex()
	var b strings.Builder
	for i := 0; i < len(s); {
		if i == 0 || !identByte(s[i-1]) {
			if orig, ok := r.matchAt(s, i); ok {
				b.WriteString(r.seen[orig])
				i += len(orig)
				continue
			}
			if digits := digitRun(s, i); digits == 12 && (i+12 == len(s) || !identByte(s[i+12])) {
				b.WriteString(r.Account(s[i : i+12]))
				i += 12
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func (r *Redactor) reindex() {
	if !r.dirty && r.index != nil {
		return
	}
	r.index = map[byte][]string{}
	for orig := range r.seen {
		r.index[orig[0]] = append(r.index[orig[0]], orig)
	}
	for _, list := range r.index {
		sort.Slice(list, func(i, j int) bool {
			if len(list[i]) != len(list[j]) {
				return len(list[i]) > len(list[j])
			}
			return list[i] < list[j]
		})
	}
	r.dirty = false
}

func (r *Redactor) matchAt(s string, i int) (string, bool) {
	for _, orig := range r.index[s[i]] {
		end := i + len(orig)
		if end <= len(s) && s[i:end] == orig && (end == len(s) || !identByte(s[end]) || !identByte(orig[len(orig)-1])) {
			return orig, true
		}
	}
	return "", false
}

// identByte reports bytes that continue a word: letters, digits, '_' and
// '-'. Everything else is a boundary, so "Sid=x", "role/x." and "x," all
// expose x. Fewer word bytes means more replacements, never fewer.
func identByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func digitRun(s string, i int) int {
	n := 0
	for i+n < len(s) && s[i+n] >= '0' && s[i+n] <= '9' {
		n++
	}
	return n
}

// Analysis redacts a document in place. Structured fields go first so that
// free text can reuse their pseudonyms.
func (r *Redactor) Analysis(a *contract.Analysis) {
	a.Snapshot.Redacted = true
	for i, acct := range a.Snapshot.Accounts {
		a.Snapshot.Accounts[i] = r.Account(acct)
	}
	sort.Strings(a.Snapshot.Accounts)
	if a.Snapshot.Organization != nil {
		org := r.remember(*a.Snapshot.Organization, "o-"+r.token("org", *a.Snapshot.Organization, 10))
		a.Snapshot.Organization = &org
	}
	for i := range a.Nodes {
		r.node(&a.Nodes[i])
	}
	for i := range a.Edges {
		r.edge(&a.Edges[i])
	}
	for i := range a.Paths {
		r.path(&a.Paths[i])
	}
	for i := range a.Findings {
		r.finding(&a.Findings[i])
	}
	for i := range a.ChokePoints {
		a.ChokePoints[i].EdgeID = r.ID(a.ChokePoints[i].EdgeID)
	}
	for _, c := range a.Cycles {
		r.ids(c)
	}
	for i := range a.FixPlan {
		s := &a.FixPlan[i]
		s.EdgeID = r.ID(s.EdgeID)
		r.ids(s.PathsCut)
		if policy, stmt, ok := cutLast(s.Target, "#"); ok {
			s.Target = r.PolicySource(policy) + "#" + stmt
		}
	}
	for i := range a.Groupings {
		g := &a.Groupings[i]
		g.Name = r.Name("grouping", g.Name)
		r.ids(g.Nodes)
	}
	for i := range a.Suppressions {
		s := &a.Suppressions[i]
		r.ids(s.Findings)
	}
	if a.Diff != nil {
		r.diffItems(&a.Diff.Added)
		r.diffItems(&a.Diff.Removed)
	}
	// Free text, after every structured identifier is known.
	for i := range a.Findings {
		f := &a.Findings[i]
		f.Message = r.Text(f.Message)
		f.Location.Path = r.Text(f.Location.Path)
		if f.Suppressed != nil {
			f.Suppressed.Reason = r.Text(f.Suppressed.Reason)
			f.Suppressed.Source = r.Text(f.Suppressed.Source)
		}
	}
	for i := range a.FixPlan {
		a.FixPlan[i].Change = r.Text(a.FixPlan[i].Change)
	}
	for i := range a.Notes {
		a.Notes[i] = r.Text(a.Notes[i])
	}
	for i := range a.Suppressions {
		s := &a.Suppressions[i]
		s.ARN = r.Text(s.ARN)
		s.Reason = r.Text(s.Reason)
	}
	if a.Diff != nil && a.Diff.Removed.Objects != nil {
		for i := range a.Diff.Removed.Objects.Findings {
			f := &a.Diff.Removed.Objects.Findings[i]
			f.Message = r.Text(f.Message)
		}
	}
	sortByID(a)
}

func (r *Redactor) ids(list []string) {
	for i, id := range list {
		list[i] = r.ID(id)
	}
}

func (r *Redactor) node(n *contract.Node) {
	n.ID = r.ID(n.ID)
	n.Account = r.Account(n.Account)
	if n.ARN != nil {
		v := r.ARN(*n.ARN)
		n.ARN = &v
	}
	if n.Path != nil {
		v := r.Path(*n.Path)
		n.Path = &v
	}
	switch n.Kind {
	case "user", "role", "group":
		n.Name = r.Name(n.Kind, n.Name)
	case "external_account":
		n.Name = r.Account(n.Name)
	case "federated":
		if !publicHosts[n.Name] {
			n.Name = r.Name("federated", n.Name)
		}
	}
	tags := make(map[string]string, len(n.Tags))
	for k, v := range n.Tags {
		tags[r.Name("tag", k)] = r.Name("tag", v)
	}
	n.Tags = tags
	if n.Group != nil {
		v := r.Name("grouping", *n.Group)
		n.Group = &v
	}
}

func (r *Redactor) edge(e *contract.Edge) {
	e.ID, e.From, e.To = r.ID(e.ID), r.ID(e.From), r.ID(e.To)
	if e.Actor != nil {
		v := r.ID(*e.Actor)
		e.Actor = &v
	}
	for i := range e.Evidence {
		ev := &e.Evidence[i]
		ev.Principal = r.ID(ev.Principal)
		ev.Policy = r.PolicySource(ev.Policy)
		if ev.Sid != "" {
			ev.Sid = r.Name("sid", ev.Sid)
		}
	}
}

func (r *Redactor) path(p *contract.Path) {
	p.ID, p.Source, p.Target = r.ID(p.ID), r.ID(p.Source), r.ID(p.Target)
	r.ids(p.Edges)
	r.ids(p.Nodes)
}

func (r *Redactor) finding(f *contract.Finding) {
	f.ID = r.ID(f.ID)
	for _, p := range []**string{&f.NodeID, &f.EdgeID, &f.PathID} {
		if *p != nil {
			v := r.ID(**p)
			*p = &v
		}
	}
	f.Location.Account = r.Account(f.Location.Account)
	f.Location.Entity = r.ARN(f.Location.Entity)
	f.Location.Policy = r.PolicySource(f.Location.Policy)
}

func (r *Redactor) diffItems(d *contract.DiffItems) {
	r.ids(d.Edges)
	r.ids(d.Paths)
	r.ids(d.Findings)
	r.ids(d.Nodes)
	if d.Objects == nil {
		return
	}
	for i := range d.Objects.Nodes {
		r.node(&d.Objects.Nodes[i])
	}
	for i := range d.Objects.Edges {
		r.edge(&d.Objects.Edges[i])
	}
	for i := range d.Objects.Paths {
		r.path(&d.Objects.Paths[i])
	}
	for i := range d.Objects.Findings {
		r.finding(&d.Objects.Findings[i])
	}
}

func cutLast(s, sep string) (before, after string, ok bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// sortByID restores deterministic order: lists sorted by ID would otherwise
// reveal the order of the original identifiers.
func sortByID(a *contract.Analysis) {
	rank := func(s string) int {
		sev, _ := rules.ParseSeverity(s)
		return sev.Rank()
	}
	sort.Slice(a.Findings, func(i, j int) bool {
		x, y := a.Findings[i], a.Findings[j]
		switch {
		case rank(x.Severity) != rank(y.Severity):
			return rank(x.Severity) < rank(y.Severity)
		case x.RuleID != y.RuleID:
			return x.RuleID < y.RuleID
		default:
			return x.ID < y.ID
		}
	})
	sort.Slice(a.ChokePoints, func(i, j int) bool {
		if a.ChokePoints[i].PathsCut != a.ChokePoints[j].PathsCut {
			return a.ChokePoints[i].PathsCut > a.ChokePoints[j].PathsCut
		}
		return a.ChokePoints[i].EdgeID < a.ChokePoints[j].EdgeID
	})
	sort.Slice(a.Nodes, func(i, j int) bool { return a.Nodes[i].ID < a.Nodes[j].ID })
	sort.Slice(a.Edges, func(i, j int) bool { return a.Edges[i].ID < a.Edges[j].ID })
	sort.SliceStable(a.Paths, func(i, j int) bool {
		if a.Paths[i].Source != a.Paths[j].Source {
			return a.Paths[i].Source < a.Paths[j].Source
		}
		if a.Paths[i].Length != a.Paths[j].Length {
			return a.Paths[i].Length < a.Paths[j].Length
		}
		return a.Paths[i].ID < a.Paths[j].ID
	})
	for i := range a.Groupings {
		sort.Strings(a.Groupings[i].Nodes)
	}
	for _, s := range a.Suppressions {
		sort.Strings(s.Findings)
	}
}
