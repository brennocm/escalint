package collect

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The snapshot envelope (docs/research.md §8). Field names follow the AWS
// CLI output of GetAccountAuthorizationDetails so the same loader reads
// both.

// Envelope is the snapshot.
type Envelope struct {
	Version     string        `json:"escalint_snapshot"`
	CollectedAt string        `json:"collected_at"`
	Collector   Collector     `json:"collector"`
	Partition   string        `json:"partition"`
	Accounts    []Account     `json:"accounts"`
	Org         *Organization `json:"organization,omitempty"`
}

// Collector identifies the build that collected the snapshot.
type Collector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Account is one account's data.
type Account struct {
	AccountID            string             `json:"account_id"`
	AuthorizationDetails AuthzDetails       `json:"authorization_details"`
	IdentityProviders    IdentityProviders  `json:"identity_providers"`
	Extras               *Extras            `json:"extras,omitempty"`
	Resources            *ResourceInventory `json:"resources,omitempty"`
}

// AuthzDetails mirrors GetAccountAuthorizationDetails.
type AuthzDetails struct {
	UserDetailList  []User    `json:"UserDetailList"`
	GroupDetailList []Group   `json:"GroupDetailList"`
	RoleDetailList  []Role    `json:"RoleDetailList"`
	Policies        []Managed `json:"Policies"`
}

// Document is a policy document: the decoded JSON object when the SDK's
// URL-encoded string decodes to valid JSON, else the string as returned
// (the loader reports it).
type Document = json.RawMessage

// Inline is an inline policy.
type Inline struct {
	PolicyName     string   `json:"PolicyName"`
	PolicyDocument Document `json:"PolicyDocument"`
}

// Attached is an attached managed policy.
type Attached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// Boundary is a permissions boundary.
type Boundary struct {
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
}

// Tag is a resource tag.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// User mirrors UserDetail.
type User struct {
	Path                    string     `json:"Path"`
	UserName                string     `json:"UserName"`
	UserID                  string     `json:"UserId"`
	Arn                     string     `json:"Arn"`
	CreateDate              string     `json:"CreateDate,omitempty"`
	UserPolicyList          []Inline   `json:"UserPolicyList"`
	GroupList               []string   `json:"GroupList"`
	AttachedManagedPolicies []Attached `json:"AttachedManagedPolicies"`
	PermissionsBoundary     *Boundary  `json:"PermissionsBoundary,omitempty"`
	Tags                    []Tag      `json:"Tags"`
}

// Group mirrors GroupDetail.
type Group struct {
	Path                    string     `json:"Path"`
	GroupName               string     `json:"GroupName"`
	GroupID                 string     `json:"GroupId"`
	Arn                     string     `json:"Arn"`
	GroupPolicyList         []Inline   `json:"GroupPolicyList"`
	AttachedManagedPolicies []Attached `json:"AttachedManagedPolicies"`
}

// InstanceProfile is a role's instance profile.
type InstanceProfile struct {
	InstanceProfileName string `json:"InstanceProfileName"`
	Arn                 string `json:"Arn"`
}

// LastUsed is RoleLastUsed.
type LastUsed struct {
	LastUsedDate string `json:"LastUsedDate,omitempty"`
	Region       string `json:"Region,omitempty"`
}

// Role mirrors RoleDetail.
type Role struct {
	Path                     string            `json:"Path"`
	RoleName                 string            `json:"RoleName"`
	RoleID                   string            `json:"RoleId"`
	Arn                      string            `json:"Arn"`
	AssumeRolePolicyDocument Document          `json:"AssumeRolePolicyDocument"`
	InstanceProfileList      []InstanceProfile `json:"InstanceProfileList"`
	RolePolicyList           []Inline          `json:"RolePolicyList"`
	AttachedManagedPolicies  []Attached        `json:"AttachedManagedPolicies"`
	PermissionsBoundary      *Boundary         `json:"PermissionsBoundary,omitempty"`
	Tags                     []Tag             `json:"Tags"`
	RoleLastUsed             *LastUsed         `json:"RoleLastUsed,omitempty"`
}

// Version is a managed policy version.
type Version struct {
	Document         Document `json:"Document"`
	VersionID        string   `json:"VersionId"`
	IsDefaultVersion bool     `json:"IsDefaultVersion"`
}

// Managed mirrors ManagedPolicyDetail.
type Managed struct {
	PolicyName        string    `json:"PolicyName"`
	PolicyID          string    `json:"PolicyId"`
	Arn               string    `json:"Arn"`
	Path              string    `json:"Path"`
	DefaultVersionID  string    `json:"DefaultVersionId"`
	PolicyVersionList []Version `json:"PolicyVersionList"`
}

// IdentityProviders lists OIDC and SAML providers.
type IdentityProviders struct {
	OIDC []OIDCProvider `json:"oidc"`
	SAML []SAMLProvider `json:"saml"`
}

// OIDCProvider is an OpenID Connect provider.
type OIDCProvider struct {
	Arn       string   `json:"arn"`
	URL       string   `json:"url"`
	ClientIDs []string `json:"client_ids"`
}

// SAMLProvider is a SAML provider.
type SAMLProvider struct {
	Arn string `json:"arn"`
}

// Extras are per-user facts that rule prerequisites need.
type Extras struct {
	AccessKeys    map[string][]AccessKey `json:"access_keys"`
	LoginProfiles map[string]bool        `json:"login_profiles"`
}

// AccessKey is the status of one access key (never its ID or secret).
type AccessKey struct {
	Status string `json:"status"`
}

// ResourceInventory lists compute resources that run with roles.
type ResourceInventory struct {
	Lambda    []LambdaFunction `json:"lambda"`
	EC2       []EC2Instance    `json:"ec2"`
	CodeBuild []CodeBuild      `json:"codebuild"`
}

// LambdaFunction is a function and its execution role.
type LambdaFunction struct {
	Arn  string `json:"arn"`
	Role string `json:"role"`
}

// EC2Instance is an instance, its profile and whether SSM manages it.
type EC2Instance struct {
	Arn             string `json:"arn"`
	InstanceProfile string `json:"instance_profile"`
	SSMManaged      bool   `json:"ssm_managed"`
}

// CodeBuild is a project and its service role.
type CodeBuild struct {
	Arn         string `json:"arn"`
	ServiceRole string `json:"service_role"`
}

// Organization is the organization tree and its SCPs and RCPs.
type Organization struct {
	ID                  string      `json:"id"`
	ManagementAccountID string      `json:"management_account_id"`
	Tree                []OrgNode   `json:"tree"`
	Policies            []OrgPolicy `json:"policies"`
}

// OrgNode is a root, OU or account.
type OrgNode struct {
	ID     string  `json:"id"`
	Type   string  `json:"type"`
	Parent *string `json:"parent"`
}

// OrgPolicy is an SCP or RCP and where it is attached.
type OrgPolicy struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Document Document `json:"document"`
	Targets  []string `json:"targets"`
}

// decodeDocument turns the SDK's URL-encoded policy string into JSON.
// PathUnescape (not QueryUnescape) keeps '+' as is, per RFC 3986.
func decodeDocument(s *string) Document {
	raw := aws.ToString(s)
	if raw == "" {
		return Document("null")
	}
	if dec, err := url.PathUnescape(raw); err == nil && json.Valid([]byte(dec)) {
		return Document(dec)
	}
	if json.Valid([]byte(raw)) {
		return Document(raw)
	}
	quoted, _ := json.Marshal(raw) // keep it; the loader reports EL-PARSE-001
	return Document(quoted)
}

func timeString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func tags(list []iamtypes.Tag) []Tag {
	out := make([]Tag, 0, len(list))
	for _, t := range list {
		out = append(out, Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
	}
	return out
}

func inlines(list []iamtypes.PolicyDetail) []Inline {
	out := make([]Inline, 0, len(list))
	for _, p := range list {
		out = append(out, Inline{PolicyName: aws.ToString(p.PolicyName), PolicyDocument: decodeDocument(p.PolicyDocument)})
	}
	return out
}

func attached(list []iamtypes.AttachedPolicy) []Attached {
	out := make([]Attached, 0, len(list))
	for _, p := range list {
		out = append(out, Attached{PolicyName: aws.ToString(p.PolicyName), PolicyArn: aws.ToString(p.PolicyArn)})
	}
	return out
}

func boundary(b *iamtypes.AttachedPermissionsBoundary) *Boundary {
	if b == nil || aws.ToString(b.PermissionsBoundaryArn) == "" {
		return nil
	}
	return &Boundary{PermissionsBoundaryType: string(b.PermissionsBoundaryType), PermissionsBoundaryArn: aws.ToString(b.PermissionsBoundaryArn)}
}
