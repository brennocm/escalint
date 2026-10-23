// Package rules holds the escalation and trust rules of escalint. Each rule
// declares its metadata (ID, pathfinding.cloud IDs, ATT&CK techniques,
// required actions…) and either adds edges to the graph (path rules) or
// reports findings directly (trust and parse rules). The registry lists them
// explicitly; there is no init() magic.
package rules

import (
	"github.com/brennocm/escalint/internal/attack"
	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/snapshot"
)

// Severity of a finding.
type Severity string

// Severities, from most to least severe.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Rank orders severities: 0 is critical, 4 is info, 5 unknown.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	case Info:
		return 4
	}
	return 5
}

// ParseSeverity validates a severity name.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(s)
	return sev, sev.Rank() < 5
}

// Status says whether a rule runs by default.
type Status string

// Rule statuses.
const (
	Stable       Status = "stable"
	Experimental Status = "experimental" // runs only with --experimental
)

// Category follows pathfinding.cloud, plus trust and parse.
type Category string

// Rule categories.
const (
	SelfEscalation   Category = "self-escalation"
	PrincipalAccess  Category = "principal-access"
	NewPassRole      Category = "new-passrole"
	ExistingPassRole Category = "existing-passrole"
	TrustCategory    Category = "trust"
	ParseCategory    Category = "parse"
)

// Metadata describes a rule.
type Metadata struct {
	ID              string
	Title           string
	Category        Category
	Severity        Severity // base severity; raised to critical on a path to Tier 0
	EdgeKind        graph.EdgeKind
	PathfindingIDs  []string
	RequiredActions []string
	Prerequisites   []string
	Status          Status
	// Attack lists ATT&CK technique IDs; names and tactics come from the
	// embedded ATT&CK data, never from here (ADR 0021).
	Attack               []string
	AttackUnmappedReason string
	Remediation          string
	References           []string
}

// AttackRef is a resolved ATT&CK technique.
type AttackRef struct {
	TechniqueID string
	Name        string
	Tactics     []string
	URL         string
}

// AttackRefs resolves the rule's technique IDs against the embedded data;
// unknown IDs are skipped (the registry test forbids them).
func (m Metadata) AttackRefs(data *attack.Data) []AttackRef {
	var out []AttackRef
	for _, id := range m.Attack {
		if t, ok := data.Lookup(id); ok {
			out = append(out, AttackRef{TechniqueID: t.ID, Name: t.Name, Tactics: t.Tactics, URL: t.URL})
		}
	}
	return out
}

// Config is the part of .escalint.yaml that rules read.
type Config struct {
	TrustedAccounts    []string // external accounts considered part of the estate
	ThirdPartyAccounts []string // vendors that must use sts:ExternalId
}

// Context is everything a rule may read.
type Context struct {
	Graph   *graph.Graph
	Env     *graph.Env
	Snap    *snapshot.Snapshot
	Catalog *catalog.Catalog
	Config  Config
}

// Finding is a result reported directly by a rule (trust and parse rules).
// Path rules report through the edges they add; the engine turns those edges
// into findings.
type Finding struct {
	RuleID   string
	Severity Severity
	NodeID   string // subject node (the role whose trust is weak, …)
	EdgeID   string // optional
	Title    string
	Message  string
	Location Location
}

// Location points at the policy behind a finding.
type Location struct {
	Account   string
	Entity    string // ARN of the user, role or group
	Policy    string // policy source (ARN, inline:…, trust:…)
	Statement int    // -1 when not tied to a statement
	Path      string // JSON path inside the document, if known
}

// Pass orders rule execution: composite rules need the edges of primitive
// rules.
type Pass int

// Passes.
const (
	PassPrimitive Pass = 1
	PassComposite Pass = 2
)

// Rule is the interface every rule implements.
type Rule interface {
	Meta() Metadata
	Pass() Pass
	// Apply adds edges to ctx.Graph and returns direct findings.
	Apply(ctx *Context) []Finding
}
