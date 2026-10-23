// Package eval decides whether a principal may perform an action on a
// resource, following the AWS policy evaluation logic documented in
// docs/research.md §2, and explains every decision with a trace.
//
// The evaluator is static: it never calls AWS. Whatever it cannot know (a
// request-time condition key, a policy that could not be parsed or was not
// collected) makes the decision Conditional instead of Allow or Deny, so a
// path that depends on it is reported, never dropped (ADR 0005).
package eval

import "github.com/brennocm/escalint/internal/policy"

// Decision is the outcome of an evaluation.
type Decision int

// Decisions, from most to least restrictive. Order matters: Less compares
// them by permissiveness.
const (
	ExplicitDeny Decision = iota
	ImplicitDeny
	Conditional
	Allow
)

func (d Decision) String() string {
	switch d {
	case ExplicitDeny:
		return "ExplicitDeny"
	case ImplicitDeny:
		return "ImplicitDeny"
	case Conditional:
		return "Conditional"
	case Allow:
		return "Allow"
	default:
		return "Decision(?)"
	}
}

// Allowed reports whether the decision is Allow or Conditional, i.e. whether
// an escalation edge should exist (with status allowed or conditional).
func (d Decision) Allowed() bool {
	return d == Allow || d == Conditional
}

// PolicyType says where a policy sits in the evaluation.
type PolicyType string

// Policy types.
const (
	TypeIdentity PolicyType = "identity"
	TypeBoundary PolicyType = "boundary"
	TypeResource PolicyType = "resource" // in v1: role trust policies
	TypeSCP      PolicyType = "scp"
	TypeRCP      PolicyType = "rcp"
)

// Policy is one policy document with where it came from. A nil Doc means
// the policy exists but its content is unknown (not collected or not
// parsable); it then counts as a possible allow and a possible deny.
type Policy struct {
	Type   PolicyType
	Source string // managed policy ARN, "inline:<entity ARN>/<name>", SCP id…
	Name   string
	Doc    *policy.Document
}

// OrgChain is the list of organization policies at every level from the
// root to the account (SCPs for principals, RCPs for resources). Each level
// must allow; a deny at any level denies.
type OrgChain struct {
	Levels [][]Policy // Levels[0] is the root
}

// PrincipalKind is the type of the identity making the request.
type PrincipalKind string

// Principal kinds.
const (
	PrincipalUser      PrincipalKind = "user"
	PrincipalRole      PrincipalKind = "role"
	PrincipalService   PrincipalKind = "service"   // e.g. lambda.amazonaws.com
	PrincipalFederated PrincipalKind = "federated" // OIDC or SAML provider
	PrincipalExternal  PrincipalKind = "external"  // any principal of an account outside the snapshot
	PrincipalAnonymous PrincipalKind = "anonymous" // stands for "any principal" ("*")
)

// Principal is the identity making the request and everything that limits
// it on its own side.
type Principal struct {
	Kind    PrincipalKind
	ARN     string // user/role ARN; provider ARN for federated; empty for service/external
	ID      string // unique ID (AIDA…/AROA…) when known; trust policies may store it
	Account string // 12-digit account, empty for services and anonymous
	Name    string // service principal name, e.g. "ec2.amazonaws.com"

	Identity []Policy // inline, attached and group policies
	// Boundary is nil when no permissions boundary is attached.
	Boundary *Policy
	// SCPs is nil when organization data is not available for the
	// principal's account or SCPs do not apply to it (management account,
	// service-linked role, account outside the organization).
	SCPs *OrgChain
	// SCPsUnknown is set when the account is in an organization whose SCPs
	// were not collected (edge case E36): SCP outcomes become Conditional.
	SCPsUnknown bool

	OrgID         string // organization of the principal's account, if known
	ServiceLinked bool
}

// Resource is the target of the request.
type Resource struct {
	ARN     string
	Account string // owner account; empty when not tied to an account
	Policy  *Policy
	// RCPs is nil when RCPs do not apply (management account, service not
	// covered by RCPs, no organization data).
	RCPs        *OrgChain
	RCPsUnknown bool
}

// Request is one authorization question.
type Request struct {
	Principal *Principal
	Action    string // "service:Action"
	Resource  *Resource
	// Context holds statically known condition keys and their values. A key
	// listed with no values is known to be absent from the request.
	Context map[string][]string
}

// Outcome of one statement against a request.
type Outcome string

// Statement outcomes recorded in the trace.
const (
	OutcomeMatch       Outcome = "match"
	OutcomeConditional Outcome = "conditional" // would match, depends on unevaluated keys
	OutcomeUnknown     Outcome = "unknown"     // policy content unknown
)

// Step is one statement (or unknown policy) that took part in the decision.
type Step struct {
	Stage     PolicyType
	Policy    string // Policy.Source
	Name      string
	Statement int // index in the document; -1 for an unknown policy
	Sid       string
	Effect    policy.Effect
	Outcome   Outcome
	Keys      []string // unevaluated condition keys, sorted
	Level     int      // organization level for SCP/RCP steps, 0 otherwise
}

// Result is a decision with its explanation.
type Result struct {
	Decision Decision
	// Decisive is the step that settled the decision: the deny for
	// ExplicitDeny, the gate that had no allow for ImplicitDeny (Statement is
	// -1 and Policy names the gate), the allow that granted access for Allow.
	Decisive *Step
	// Steps lists every matching or conditional statement, in evaluation
	// order (denies first, then RCP, SCP, resource, identity, boundary).
	Steps []Step
	// Unevaluated lists every condition key that made the result
	// Conditional, sorted and without duplicates.
	Unevaluated []string
	// Notes explain gates that were skipped (for example "SCPs not
	// evaluated: no organization data").
	Notes []string
}
