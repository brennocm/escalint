// Package snapshot loads an IAM snapshot: the output of
// GetAccountAuthorizationDetails, optionally wrapped in the escalint
// envelope with organization policies, identity providers and a resource
// inventory (docs/research.md §8).
//
// Loading never fails because one policy is malformed: the policy is kept
// with a nil Document and a Diagnostic (EL-PARSE-001) explains why, so the
// rest of the account is still analyzed.
package snapshot

import (
	"sort"
	"time"

	"github.com/brennocm/escalint/internal/policy"
)

// Format names the input shape that was detected.
type Format string

// Supported input formats.
const (
	FormatEnvelope             Format = "envelope"
	FormatAuthorizationDetails Format = "authorization-details"
)

// Snapshot is the loaded, validated and resolved input of an analysis.
type Snapshot struct {
	Format       Format
	CollectedAt  time.Time // zero when unknown
	Partition    string
	Accounts     []*Account // sorted by ID
	Organization *Organization
	Diagnostics  []Diagnostic // sorted
}

// Account holds the IAM entities of one AWS account.
type Account struct {
	ID                string
	Users             []*User  // sorted by ARN
	Groups            []*Group // sorted by ARN
	Roles             []*Role  // sorted by ARN
	Policies          []*ManagedPolicy
	IdentityProviders IdentityProviders
	Extras            *Extras    // nil when not collected
	Resources         *Resources // nil when not collected

	policyByARN map[string]*ManagedPolicy
	groupByName map[string]*Group
}

// Policy returns the managed policy with the given ARN, or nil.
func (a *Account) Policy(arn string) *ManagedPolicy {
	return a.policyByARN[arn]
}

// Group returns the group with the given name, or nil.
func (a *Account) Group(name string) *Group {
	return a.groupByName[name]
}

// InlinePolicy is a policy embedded in a user, group or role. Document is
// nil when the policy could not be parsed (see Snapshot.Diagnostics).
type InlinePolicy struct {
	Name     string
	Document *policy.Document
}

// ManagedPolicy is a customer or AWS managed policy at its default version.
type ManagedPolicy struct {
	ARN            string
	Name           string
	Path           string
	DefaultVersion string
	AWSManaged     bool
	Document       *policy.Document // nil when unparsable or no default version
}

// Tag is an IAM tag.
type Tag struct {
	Key   string
	Value string
}

// User is an IAM user.
type User struct {
	ARN                 string
	Name                string
	ID                  string
	Path                string
	Groups              []*Group // resolved from GroupList, sorted by ARN
	Inline              []InlinePolicy
	Attached            []string // managed policy ARNs, sorted
	PermissionsBoundary string   // policy ARN, empty when none
	Tags                []Tag    // sorted by key
}

// Group is an IAM group.
type Group struct {
	ARN      string
	Name     string
	ID       string
	Path     string
	Inline   []InlinePolicy
	Attached []string
}

// Role is an IAM role.
type Role struct {
	ARN                 string
	Name                string
	ID                  string
	Path                string
	Trust               *policy.Document // nil when unparsable
	Inline              []InlinePolicy
	Attached            []string
	PermissionsBoundary string
	Tags                []Tag
	InstanceProfiles    []string   // instance profile ARNs, sorted
	LastUsed            *time.Time // nil when never used or not reported
	ServiceLinked       bool       // path /aws-service-role/
}

// IdentityProviders lists the OIDC and SAML providers of an account.
type IdentityProviders struct {
	OIDC []OIDCProvider
	SAML []SAMLProvider
}

// OIDCProvider is an IAM OpenID Connect provider.
type OIDCProvider struct {
	ARN       string
	URL       string
	ClientIDs []string
}

// SAMLProvider is an IAM SAML provider.
type SAMLProvider struct {
	ARN string
}

// Extras holds optional per-user facts that some prerequisites need.
type Extras struct {
	AccessKeys    map[string]int  // user ARN -> number of access keys
	LoginProfiles map[string]bool // user ARN -> has a console password
}

// Resources is the optional inventory used by update_code edges.
type Resources struct {
	Lambda    []LambdaFunction
	EC2       []EC2Instance
	CodeBuild []CodeBuildProject
}

// LambdaFunction is a function and its execution role.
type LambdaFunction struct {
	ARN  string
	Role string
}

// EC2Instance is an instance and its instance profile.
type EC2Instance struct {
	ARN             string
	InstanceProfile string
	SSMManaged      bool
}

// CodeBuildProject is a project and its service role.
type CodeBuildProject struct {
	ARN         string
	ServiceRole string
}

// Diagnostic codes.
const (
	CodeParse      = "EL-PARSE-001" // a policy document could not be parsed
	CodeUnresolved = "EL-PARSE-002" // a reference points to nothing in the snapshot
)

// Diagnostic is a non-fatal problem found while loading.
type Diagnostic struct {
	Code    string
	Account string
	Entity  string // ARN of the user, group, role or policy
	Policy  string // inline policy name or managed policy ARN
	Path    string // location inside the policy document
	Message string
}

func sortDiagnostics(d []Diagnostic) {
	// Every field takes part in the order, so equal-looking diagnostics that
	// differ only in Path cannot swap places between runs.
	sort.SliceStable(d, func(i, j int) bool {
		a, b := d[i], d[j]
		switch {
		case a.Account != b.Account:
			return a.Account < b.Account
		case a.Entity != b.Entity:
			return a.Entity < b.Entity
		case a.Policy != b.Policy:
			return a.Policy < b.Policy
		case a.Code != b.Code:
			return a.Code < b.Code
		case a.Path != b.Path:
			return a.Path < b.Path
		default:
			return a.Message < b.Message
		}
	})
}
