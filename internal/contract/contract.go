// Package contract is the analysis.json document (schema_version "1"), the
// contract between the engine and the web UI. schema/analysis.v1.schema.json
// is the source of truth (ADR 0003); these structs mirror it and a test
// validates generated documents against it.
package contract

import "encoding/json"

// SchemaVersion is the version of the contract these structs implement.
const SchemaVersion = "1"

// Analysis is the root document.
type Analysis struct {
	SchemaVersion string         `json:"schema_version"`
	Generator     Generator      `json:"generator"`
	Snapshot      SnapshotInfo   `json:"snapshot"`
	Catalogs      Catalogs       `json:"catalogs"`
	Options       RunOptions     `json:"options"`
	Rules         []Rule         `json:"rules"`
	Nodes         []Node         `json:"nodes"`
	Edges         []Edge         `json:"edges"`
	Paths         []Path         `json:"paths"`
	Findings      []Finding      `json:"findings"`
	Suppressions  []Suppression  `json:"suppressions"`
	ChokePoints   []ChokePoint   `json:"choke_points"`
	Cycles        [][]string     `json:"cycles"`
	FixPlan       []FixStep      `json:"fix_plan"`
	Notes         []string       `json:"notes"`
	Stats         Stats          `json:"stats"`
	Diff          *Diff          `json:"diff,omitempty"`
	Groupings     []Grouping     `json:"groupings"`
	Attack        AttackCoverage `json:"attack"`
	// Policies are the documents cited by edge evidence, for the policy
	// explainer. Empty when redacted (documents can hold identifiers that
	// redaction cannot recognize, such as condition values).
	Policies []PolicyDoc `json:"policies"`
}

// PolicyDoc is a policy document cited by evidence.
type PolicyDoc struct {
	Source   string          `json:"source"` // as in evidence[].policy
	Name     string          `json:"name"`
	Type     string          `json:"type"` // identity, boundary, trust
	Document json.RawMessage `json:"document"`
}

// Generator identifies the escalint build.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// SnapshotInfo describes the input.
type SnapshotInfo struct {
	Format      string   `json:"format"`
	CollectedAt *string  `json:"collected_at"` // RFC 3339, null when unknown
	Partition   string   `json:"partition"`
	Accounts    []string `json:"accounts"`
	Redacted    bool     `json:"redacted"`
	// Organization is the analyzed organization ID, null without one.
	Organization *string `json:"organization"`
}

// Catalogs are the versions of the embedded reference data.
type Catalogs struct {
	ServiceReference string `json:"service_reference"` // generation date
	Pathfinding      string `json:"pathfinding"`       // commit
	Attack           string `json:"attack"`            // ATT&CK release
}

// RunOptions records the options that shaped the result.
type RunOptions struct {
	MaxDepth     int      `json:"max_depth"`
	KPaths       int      `json:"k_paths"`
	Experimental bool     `json:"experimental"`
	MinSeverity  string   `json:"min_severity"`
	EnabledRules []string `json:"enabled_rules"`
}

// Rule is the metadata of an enabled rule.
type Rule struct {
	ID                   string      `json:"id"`
	Title                string      `json:"title"`
	Category             string      `json:"category"`
	Severity             string      `json:"severity"`
	Status               string      `json:"status"`
	EdgeKind             *string     `json:"edge_kind"`
	PathfindingIDs       []string    `json:"pathfinding_ids"`
	RequiredActions      []string    `json:"required_actions"`
	Prerequisites        []string    `json:"prerequisites"`
	Attack               []Technique `json:"attack"`
	AttackUnmappedReason *string     `json:"attack_unmapped_reason"`
	Remediation          string      `json:"remediation"`
	References           []string    `json:"references"`
}

// Technique is a resolved ATT&CK technique.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	URL     string   `json:"url"`
}

// Node is a principal, a principal type outside the snapshot, or a sink.
type Node struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	ARN             *string           `json:"arn"`
	Name            string            `json:"name"`
	Account         string            `json:"account"`
	Path            *string           `json:"path"`
	Tags            map[string]string `json:"tags"`
	Tier            int               `json:"tier"`
	TierConditional bool              `json:"tier_conditional"`
	ServiceLinked   bool              `json:"service_linked"`
	Blast           *Blast            `json:"blast"`
	LastUsed        *string           `json:"last_used"`
	Flags           []string          `json:"flags"`
	Group           *string           `json:"group"` // UI grouping from .escalint.yaml
}

// Blast is the blast radius vector of a principal.
type Blast struct {
	ReachablePrincipals int          `json:"reachable_principals"`
	ReachesTier0        bool         `json:"reaches_tier0"`
	Capabilities        Capabilities `json:"capabilities"`
}

// Capabilities lists services by the strongest capability class.
type Capabilities struct {
	PermissionManagement []string `json:"permission_management"`
	Write                []string `json:"write"`
	Read                 []string `json:"read"`
	List                 []string `json:"list"`
}

// Edge is a "can act as" relation.
type Edge struct {
	ID                      string     `json:"id"`
	From                    string     `json:"from"`
	To                      string     `json:"to"`
	Kind                    string     `json:"kind"`
	RuleIDs                 []string   `json:"rule_ids"`
	PathfindingIDs          []string   `json:"pathfinding_ids"`
	Status                  string     `json:"status"`
	RequiredActions         []string   `json:"required_actions"`
	Evidence                []Evidence `json:"evidence"`
	ConditionsUnevaluated   []string   `json:"conditions_unevaluated"`
	PrerequisitesUnverified []string   `json:"prerequisites_unverified"`
	Latent                  bool       `json:"latent"`
	Actor                   *string    `json:"actor"`
	Attack                  []string   `json:"attack"` // technique IDs of the edge's rules
	Detection               Detection  `json:"detection"`
}

// Evidence is one policy statement behind an edge.
type Evidence struct {
	Principal      string `json:"principal"`
	Action         string `json:"action"`
	Policy         string `json:"policy"`
	StatementIndex int    `json:"statement_index"`
	Sid            string `json:"sid"`
	Effect         string `json:"effect"`
	Stage          string `json:"stage"`
}

// Detection tells which CloudTrail events the step produces (ADR 0022).
type Detection struct {
	Events             []Event  `json:"events"`
	BlindSpots         []string `json:"blind_spots"`
	RequiresDataEvents bool     `json:"requires_data_events"`
	Status             string   `json:"status"`
	Visibility         string   `json:"visibility"`
}

// Event is one CloudTrail event.
type Event struct {
	Source    string   `json:"source"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	KeyFields []string `json:"key_fields"`
	Region    string   `json:"region"`
	Notes     string   `json:"notes"`
}

// Path is an enumerated escalation path.
type Path struct {
	ID       string   `json:"id"`
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Edges    []string `json:"edges"`
	Nodes    []string `json:"nodes"`
	Length   int      `json:"length"`
	Status   string   `json:"status"`
	Severity string   `json:"severity"`
}

// Finding is one reported problem.
type Finding struct {
	ID          string      `json:"id"`
	RuleID      string      `json:"rule_id"`
	Severity    string      `json:"severity"`
	Title       string      `json:"title"`
	Message     string      `json:"message"`
	NodeID      *string     `json:"node_id"`
	EdgeID      *string     `json:"edge_id"`
	PathID      *string     `json:"path_id"`
	Latent      bool        `json:"latent"`
	Location    Location    `json:"location"`
	Remediation string      `json:"remediation"`
	Suppressed  *Suppressed `json:"suppressed"`
}

// Location points at the policy behind a finding.
type Location struct {
	Account        string `json:"account"`
	Entity         string `json:"entity"`
	Policy         string `json:"policy"`
	StatementIndex int    `json:"statement_index"` // -1 when unknown
	Path           string `json:"path"`
	Line           *int   `json:"line"` // in the snapshot file, null without one
}

// Suppressed explains why a finding is suppressed.
type Suppressed struct {
	Reason  string  `json:"reason"`
	Expires *string `json:"expires"`
	Source  string  `json:"source"`
}

// Suppression is one entry of .escalint.yaml and the findings it matched.
type Suppression struct {
	Rule     string   `json:"rule"`
	ARN      string   `json:"arn"`
	Reason   string   `json:"reason"`
	Expires  *string  `json:"expires"`
	Status   string   `json:"status"` // active, expired, unjustified
	Findings []string `json:"findings"`
}

// ChokePoint is an edge shared by enumerated paths.
type ChokePoint struct {
	EdgeID   string  `json:"edge_id"`
	PathsCut int     `json:"paths_cut"`
	Share    float64 `json:"share"`
}

// FixStep is one change of the fix plan.
type FixStep struct {
	Order    int      `json:"order"`
	EdgeID   string   `json:"edge_id"`
	Change   string   `json:"change"`
	Target   string   `json:"target"`
	PathsCut []string `json:"paths_cut"`
}

// Stats summarizes the result.
type Stats struct {
	Nodes      int    `json:"nodes"`
	Edges      int    `json:"edges"`
	Paths      int    `json:"paths"`
	Findings   int    `json:"findings"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
}

// Grouping is a named set of nodes for the UI.
type Grouping struct {
	Name  string   `json:"name"`
	Nodes []string `json:"nodes"`
}

// AttackCoverage summarizes the ATT&CK techniques of the findings.
type AttackCoverage struct {
	Version    string           `json:"version"`
	Techniques []TechniqueCount `json:"techniques"`
}

// TechniqueCount is a technique and the findings that exhibit it.
type TechniqueCount struct {
	ID       string `json:"id"`
	Findings int    `json:"findings"`
	Paths    int    `json:"paths"`
}

// Diff marks what changed against a baseline analysis.
type Diff struct {
	Base    DiffBase  `json:"base"`
	Added   DiffItems `json:"added"`
	Removed DiffItems `json:"removed"`
}

// DiffBase identifies the baseline.
type DiffBase struct {
	CollectedAt *string `json:"collected_at"`
	Generator   string  `json:"generator"`
}

// DiffItems lists IDs (removed items also keep their objects so the UI can
// draw them).
type DiffItems struct {
	Edges    []string `json:"edges"`
	Paths    []string `json:"paths"`
	Findings []string `json:"findings"`
	Nodes    []string `json:"nodes"`
	Objects  *Removed `json:"objects,omitempty"`
}

// Removed holds the objects that exist only in the baseline.
type Removed struct {
	Nodes    []Node    `json:"nodes"`
	Edges    []Edge    `json:"edges"`
	Paths    []Path    `json:"paths"`
	Findings []Finding `json:"findings"`
}
