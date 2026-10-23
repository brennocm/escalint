package snapshot

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/brennocm/escalint/internal/arn"
	"github.com/brennocm/escalint/internal/jsonx"
	"github.com/brennocm/escalint/internal/policy"
)

// ErrLimitExceeded is wrapped by errors caused by a configured limit.
var ErrLimitExceeded = errors.New("limit exceeded")

// Options bounds the work spent on one snapshot. The zero value uses the
// defaults below.
type Options struct {
	MaxBytes      int64 // default 200 MB
	MaxDepth      int   // JSON nesting of the whole file, default 64
	MaxPrincipals int   // users + groups + roles over all accounts, default 200,000
	Policy        policy.Limits
}

func (o Options) withDefaults() Options {
	if o.MaxBytes <= 0 {
		o.MaxBytes = 200 << 20
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 64
	}
	if o.MaxPrincipals <= 0 {
		o.MaxPrincipals = 200_000
	}
	return o
}

// LoadFile opens path and calls Load.
func LoadFile(path string, opts Options) (*Snapshot, error) {
	f, err := os.Open(path) // #nosec G304 -- the user chooses which snapshot to analyze
	if err != nil {
		return nil, fmt.Errorf("open snapshot: %w", err)
	}
	defer f.Close()
	return Load(f, opts)
}

// Load reads, validates and resolves a snapshot. Structural problems with
// the file (invalid JSON, limits, unknown format, inconsistent accounts) are
// errors; problems inside individual policies are Diagnostics.
func Load(r io.Reader, opts Options) (*Snapshot, error) {
	opts = opts.withDefaults()
	data, err := io.ReadAll(io.LimitReader(r, opts.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if int64(len(data)) > opts.MaxBytes {
		return nil, fmt.Errorf("snapshot is larger than %d bytes: %w", opts.MaxBytes, ErrLimitExceeded)
	}
	// Files written by some Windows tools start with a UTF-8 byte order mark,
	// which encoding/json rejects.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	if err := jsonx.Check(data, opts.MaxDepth); err != nil {
		if errors.Is(err, jsonx.ErrTooDeep) {
			return nil, fmt.Errorf("snapshot: %w: %w", ErrLimitExceeded, err)
		}
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	names, err := topLevelNames(data)
	if err != nil {
		return nil, err
	}

	var snap *Snapshot
	switch {
	case names["escalint_snapshot"]:
		snap, err = loadEnvelope(data, opts)
	case isAuthorizationDetails(names):
		snap, err = loadAuthorizationDetails(data, opts)
	default:
		return nil, errors.New("snapshot: unknown format: expected an escalint envelope " +
			"or the output of 'aws iam get-account-authorization-details'")
	}
	if err != nil {
		return nil, err
	}
	sortDiagnostics(snap.Diagnostics)
	return snap, nil
}

// topLevelNames returns the member names of the top-level object without
// copying their values (a snapshot can be hundreds of megabytes).
func topLevelNames(data []byte) (map[string]bool, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	tok, err := dec.ReadToken()
	if err != nil || tok.Kind() != '{' {
		return nil, errors.New("snapshot must be a JSON object")
	}
	names := map[string]bool{}
	for dec.PeekKind() != '}' {
		name, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("snapshot: %w", err)
		}
		names[name.String()] = true
		if err := dec.SkipValue(); err != nil {
			return nil, fmt.Errorf("snapshot: %w", err)
		}
	}
	return names, nil
}

func isAuthorizationDetails(names map[string]bool) bool {
	for _, k := range []string{"UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"} {
		if names[k] {
			return true
		}
	}
	return false
}

func loadEnvelope(data []byte, opts Options) (*Snapshot, error) {
	var w wireEnvelope
	if err := jsonv2.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("snapshot envelope: %w", err)
	}
	if w.Version != "1" {
		return nil, fmt.Errorf("snapshot envelope version %q is not supported (expected \"1\")", w.Version)
	}
	if len(w.Accounts) == 0 {
		return nil, errors.New("snapshot envelope has no accounts")
	}
	snap := &Snapshot{Format: FormatEnvelope, Partition: w.Partition}
	if w.CollectedAt != "" {
		t, err := time.Parse(time.RFC3339, w.CollectedAt)
		if err != nil {
			return nil, fmt.Errorf("snapshot envelope collected_at: %w", err)
		}
		snap.CollectedAt = t.UTC()
	}

	seen := map[string]bool{}
	principals := 0
	for i := range w.Accounts {
		wa := &w.Accounts[i]
		if !arn.IsAccountID(wa.AccountID) {
			return nil, fmt.Errorf("snapshot account %d: %q is not a 12-digit account ID", i, wa.AccountID)
		}
		if seen[wa.AccountID] {
			return nil, fmt.Errorf("snapshot account %q appears twice", wa.AccountID)
		}
		seen[wa.AccountID] = true
		principals += countPrincipals(&wa.AuthorizationDetails)
		if principals > opts.MaxPrincipals {
			return nil, fmt.Errorf("snapshot has more than %d principals: %w", opts.MaxPrincipals, ErrLimitExceeded)
		}
		acct, partition, diags, err := buildAccount(wa.AccountID, &wa.AuthorizationDetails, opts.Policy)
		if err != nil {
			return nil, fmt.Errorf("snapshot account %s: %w", wa.AccountID, err)
		}
		if err := setPartition(snap, partition); err != nil {
			return nil, err
		}
		applyOptional(acct, wa)
		snap.Accounts = append(snap.Accounts, acct)
		snap.Diagnostics = append(snap.Diagnostics, diags...)
	}
	if snap.Partition == "" {
		snap.Partition = "aws"
	}
	sort.Slice(snap.Accounts, func(i, j int) bool { return snap.Accounts[i].ID < snap.Accounts[j].ID })

	if w.Organization != nil {
		org, diags, err := buildOrganization(w.Organization, opts.Policy)
		if err != nil {
			return nil, fmt.Errorf("snapshot organization: %w", err)
		}
		snap.Organization = org
		snap.Diagnostics = append(snap.Diagnostics, diags...)
	}
	return snap, nil
}

func loadAuthorizationDetails(data []byte, opts Options) (*Snapshot, error) {
	var w wireAuthorizationDetails
	if err := jsonv2.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("authorization details: %w", err)
	}
	if countPrincipals(&w) > opts.MaxPrincipals {
		return nil, fmt.Errorf("snapshot has more than %d principals: %w", opts.MaxPrincipals, ErrLimitExceeded)
	}
	accountID, err := inferAccount(&w)
	if err != nil {
		return nil, err
	}
	acct, partition, diags, err := buildAccount(accountID, &w, opts.Policy)
	if err != nil {
		return nil, fmt.Errorf("authorization details: %w", err)
	}
	if partition == "" {
		partition = "aws"
	}
	return &Snapshot{
		Format:      FormatAuthorizationDetails,
		Partition:   partition,
		Accounts:    []*Account{acct},
		Diagnostics: diags,
	}, nil
}

func countPrincipals(w *wireAuthorizationDetails) int {
	return len(w.UserDetailList) + len(w.GroupDetailList) + len(w.RoleDetailList)
}

// inferAccount reads the account ID from the first entity ARN. buildAccount
// then checks that every entity belongs to it.
func inferAccount(w *wireAuthorizationDetails) (string, error) {
	arns := make([]string, 0, len(w.UserDetailList)+len(w.GroupDetailList)+len(w.RoleDetailList)+len(w.Policies))
	for _, u := range w.UserDetailList {
		arns = append(arns, u.Arn)
	}
	for _, g := range w.GroupDetailList {
		arns = append(arns, g.Arn)
	}
	for _, r := range w.RoleDetailList {
		arns = append(arns, r.Arn)
	}
	for _, p := range w.Policies {
		arns = append(arns, p.Arn)
	}
	for _, s := range arns {
		a, err := arn.Parse(s)
		if err != nil {
			return "", fmt.Errorf("authorization details: %w", err)
		}
		if arn.IsAccountID(a.Account) {
			return a.Account, nil
		}
	}
	return "", errors.New("authorization details: cannot infer the account ID (no customer entity ARNs)")
}

func setPartition(snap *Snapshot, partition string) error {
	switch {
	case partition == "":
	case snap.Partition == "":
		snap.Partition = partition
	case snap.Partition != partition:
		return fmt.Errorf("snapshot mixes partitions %q and %q", snap.Partition, partition)
	}
	return nil
}

// entityARN validates that an entity ARN belongs to the account and returns
// its partition.
func entityARN(s, accountID, kind string) (string, error) {
	a, err := arn.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%s: %w", kind, err)
	}
	if a.Service != "iam" {
		return "", fmt.Errorf("%s %q is not an IAM ARN", kind, s)
	}
	if a.Account != accountID {
		return "", fmt.Errorf("%s %q does not belong to account %s", kind, s, accountID)
	}
	return a.Partition, nil
}

func buildAccount(accountID string, w *wireAuthorizationDetails, limits policy.Limits) (*Account, string, []Diagnostic, error) {
	acct := &Account{ID: accountID, policyByARN: map[string]*ManagedPolicy{}, groupByName: map[string]*Group{}}
	var diags []Diagnostic
	partition := ""
	notePartition := func(p string) error {
		if partition == "" {
			partition = p
		} else if p != partition {
			return fmt.Errorf("account mixes partitions %q and %q", partition, p)
		}
		return nil
	}
	diag := func(d *Diagnostic, entity, policyName string) {
		if d == nil {
			return
		}
		d.Account = accountID
		d.Entity = entity
		d.Policy = policyName
		diags = append(diags, *d)
	}

	for _, wp := range w.Policies {
		a, err := arn.Parse(wp.Arn)
		if err != nil {
			return nil, "", nil, fmt.Errorf("managed policy: %w", err)
		}
		awsManaged := a.Account == "aws"
		if !awsManaged && a.Account != accountID {
			return nil, "", nil, fmt.Errorf("managed policy %q does not belong to account %s", wp.Arn, accountID)
		}
		if err := notePartition(a.Partition); err != nil {
			return nil, "", nil, err
		}
		if acct.policyByARN[wp.Arn] != nil {
			return nil, "", nil, fmt.Errorf("managed policy %q appears twice", wp.Arn)
		}
		mp := &ManagedPolicy{ARN: wp.Arn, Name: wp.PolicyName, Path: wp.Path, DefaultVersion: wp.DefaultVersionID, AWSManaged: awsManaged}
		raw := defaultVersionDocument(&wp)
		if raw == nil {
			diags = append(diags, Diagnostic{
				Code: CodeUnresolved, Account: accountID, Entity: wp.Arn, Policy: wp.Arn,
				Message: fmt.Sprintf("no document for default version %q", wp.DefaultVersionID),
			})
		} else {
			doc, d := parseDocument(raw, policy.KindIdentity, limits)
			mp.Document = doc
			diag(d, wp.Arn, wp.Arn)
		}
		acct.policyByARN[wp.Arn] = mp
		acct.Policies = append(acct.Policies, mp)
	}
	sort.Slice(acct.Policies, func(i, j int) bool { return acct.Policies[i].ARN < acct.Policies[j].ARN })

	attached := func(entity string, list []wireAttachedPolicy) []string {
		out := make([]string, 0, len(list))
		for _, ap := range list {
			out = append(out, ap.PolicyArn)
			if acct.policyByARN[ap.PolicyArn] == nil {
				diags = append(diags, Diagnostic{
					Code: CodeUnresolved, Account: accountID, Entity: entity, Policy: ap.PolicyArn,
					Message: "attached managed policy is not in the snapshot; its permissions are unknown",
				})
			}
		}
		sort.Strings(out)
		return out
	}
	boundary := func(entity string, b *wireBoundary) string {
		if b == nil || b.PermissionsBoundaryArn == "" {
			return ""
		}
		if acct.policyByARN[b.PermissionsBoundaryArn] == nil {
			diags = append(diags, Diagnostic{
				Code: CodeUnresolved, Account: accountID, Entity: entity, Policy: b.PermissionsBoundaryArn,
				Message: "permissions boundary policy is not in the snapshot; its limits are unknown",
			})
		}
		return b.PermissionsBoundaryArn
	}
	inline := func(entity string, list []wirePolicyDetail) []InlinePolicy {
		out := make([]InlinePolicy, 0, len(list))
		for _, pd := range list {
			doc, d := parseDocument(pd.PolicyDocument, policy.KindIdentity, limits)
			diag(d, entity, pd.PolicyName)
			out = append(out, InlinePolicy{Name: pd.PolicyName, Document: doc})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}

	for _, wg := range w.GroupDetailList {
		p, err := entityARN(wg.Arn, accountID, "group")
		if err != nil {
			return nil, "", nil, err
		}
		if err := notePartition(p); err != nil {
			return nil, "", nil, err
		}
		if acct.groupByName[wg.GroupName] != nil {
			return nil, "", nil, fmt.Errorf("group %q appears twice", wg.GroupName)
		}
		g := &Group{
			ARN: wg.Arn, Name: wg.GroupName, ID: wg.GroupID, Path: wg.Path,
			Inline:   inline(wg.Arn, wg.GroupPolicyList),
			Attached: attached(wg.Arn, wg.AttachedManagedPolicies),
		}
		acct.groupByName[g.Name] = g
		acct.Groups = append(acct.Groups, g)
	}
	sort.Slice(acct.Groups, func(i, j int) bool { return acct.Groups[i].ARN < acct.Groups[j].ARN })

	seenUsers := map[string]bool{}
	for _, wu := range w.UserDetailList {
		p, err := entityARN(wu.Arn, accountID, "user")
		if err != nil {
			return nil, "", nil, err
		}
		if err := notePartition(p); err != nil {
			return nil, "", nil, err
		}
		if seenUsers[wu.Arn] {
			return nil, "", nil, fmt.Errorf("user %q appears twice", wu.Arn)
		}
		seenUsers[wu.Arn] = true
		u := &User{
			ARN: wu.Arn, Name: wu.UserName, ID: wu.UserID, Path: wu.Path,
			Inline:              inline(wu.Arn, wu.UserPolicyList),
			Attached:            attached(wu.Arn, wu.AttachedManagedPolicies),
			PermissionsBoundary: boundary(wu.Arn, wu.PermissionsBoundary),
			Tags:                tags(wu.Tags),
		}
		member := map[string]bool{}
		for _, name := range wu.GroupList {
			if member[name] {
				continue // a repeated group name adds nothing
			}
			member[name] = true
			g := acct.groupByName[name]
			if g == nil {
				diags = append(diags, Diagnostic{
					Code: CodeUnresolved, Account: accountID, Entity: wu.Arn,
					Message: fmt.Sprintf("member of group %q, which is not in the snapshot", name),
				})
				continue
			}
			u.Groups = append(u.Groups, g)
		}
		sort.Slice(u.Groups, func(i, j int) bool { return u.Groups[i].ARN < u.Groups[j].ARN })
		acct.Users = append(acct.Users, u)
	}
	sort.Slice(acct.Users, func(i, j int) bool { return acct.Users[i].ARN < acct.Users[j].ARN })

	seenRoles := map[string]bool{}
	for _, wr := range w.RoleDetailList {
		p, err := entityARN(wr.Arn, accountID, "role")
		if err != nil {
			return nil, "", nil, err
		}
		if err := notePartition(p); err != nil {
			return nil, "", nil, err
		}
		if seenRoles[wr.Arn] {
			return nil, "", nil, fmt.Errorf("role %q appears twice", wr.Arn)
		}
		seenRoles[wr.Arn] = true
		r := &Role{
			ARN: wr.Arn, Name: wr.RoleName, ID: wr.RoleID, Path: wr.Path,
			Inline:              inline(wr.Arn, wr.RolePolicyList),
			Attached:            attached(wr.Arn, wr.AttachedManagedPolicies),
			PermissionsBoundary: boundary(wr.Arn, wr.PermissionsBoundary),
			Tags:                tags(wr.Tags),
			ServiceLinked:       strings.HasPrefix(wr.Path, "/aws-service-role/"),
		}
		trust, d := parseDocument(wr.AssumeRolePolicyDocument, policy.KindResource, limits)
		r.Trust = trust
		diag(d, wr.Arn, "trust policy")
		for _, ip := range wr.InstanceProfileList {
			r.InstanceProfiles = append(r.InstanceProfiles, ip.Arn)
		}
		sort.Strings(r.InstanceProfiles)
		if wr.RoleLastUsed != nil && wr.RoleLastUsed.LastUsedDate != "" {
			t, err := time.Parse(time.RFC3339, wr.RoleLastUsed.LastUsedDate)
			if err != nil {
				return nil, "", nil, fmt.Errorf("role %q: RoleLastUsed.LastUsedDate: %w", wr.Arn, err)
			}
			t = t.UTC()
			r.LastUsed = &t
		}
		acct.Roles = append(acct.Roles, r)
	}
	sort.Slice(acct.Roles, func(i, j int) bool { return acct.Roles[i].ARN < acct.Roles[j].ARN })
	return acct, partition, diags, nil
}

// defaultVersionDocument returns the document of the default version.
// DefaultVersionId is authoritative; IsDefaultVersion is only a fallback
// for inputs that omit the ID.
func defaultVersionDocument(wp *wireManagedPolicy) []byte {
	if wp.DefaultVersionID != "" {
		for _, v := range wp.PolicyVersionList {
			if v.VersionID == wp.DefaultVersionID {
				return v.Document
			}
		}
		return nil
	}
	for _, v := range wp.PolicyVersionList {
		if v.IsDefaultVersion {
			return v.Document
		}
	}
	return nil
}

func tags(list []wireTag) []Tag {
	out := make([]Tag, 0, len(list))
	for _, t := range list {
		out = append(out, Tag(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func applyOptional(acct *Account, wa *wireAccount) {
	if ip := wa.IdentityProviders; ip != nil {
		for _, p := range ip.OIDC {
			acct.IdentityProviders.OIDC = append(acct.IdentityProviders.OIDC, OIDCProvider{ARN: p.Arn, URL: p.URL, ClientIDs: p.ClientIDs})
		}
		for _, p := range ip.SAML {
			acct.IdentityProviders.SAML = append(acct.IdentityProviders.SAML, SAMLProvider{ARN: p.Arn})
		}
		sort.Slice(acct.IdentityProviders.OIDC, func(i, j int) bool {
			return acct.IdentityProviders.OIDC[i].ARN < acct.IdentityProviders.OIDC[j].ARN
		})
		sort.Slice(acct.IdentityProviders.SAML, func(i, j int) bool {
			return acct.IdentityProviders.SAML[i].ARN < acct.IdentityProviders.SAML[j].ARN
		})
	}
	if ex := wa.Extras; ex != nil {
		acct.Extras = &Extras{AccessKeys: map[string]int{}, LoginProfiles: map[string]bool{}}
		for user, keys := range ex.AccessKeys {
			acct.Extras.AccessKeys[user] = len(keys)
		}
		for user, has := range ex.LoginProfiles {
			acct.Extras.LoginProfiles[user] = has
		}
	}
	if res := wa.Resources; res != nil {
		acct.Resources = &Resources{}
		for _, f := range res.Lambda {
			acct.Resources.Lambda = append(acct.Resources.Lambda, LambdaFunction{ARN: f.Arn, Role: f.Role})
		}
		for _, i := range res.EC2 {
			acct.Resources.EC2 = append(acct.Resources.EC2, EC2Instance{ARN: i.Arn, InstanceProfile: i.InstanceProfile, SSMManaged: i.SSMManaged})
		}
		for _, p := range res.CodeBuild {
			acct.Resources.CodeBuild = append(acct.Resources.CodeBuild, CodeBuildProject{ARN: p.Arn, ServiceRole: p.ServiceRole})
		}
		sort.Slice(acct.Resources.Lambda, func(i, j int) bool { return acct.Resources.Lambda[i].ARN < acct.Resources.Lambda[j].ARN })
		sort.Slice(acct.Resources.EC2, func(i, j int) bool { return acct.Resources.EC2[i].ARN < acct.Resources.EC2[j].ARN })
		sort.Slice(acct.Resources.CodeBuild, func(i, j int) bool { return acct.Resources.CodeBuild[i].ARN < acct.Resources.CodeBuild[j].ARN })
	}
}

// parseDocument decodes a raw policy document and parses it. A nil Document
// with a Diagnostic means the policy is kept but contributes nothing.
func parseDocument(raw []byte, kind policy.Kind, limits policy.Limits) (*policy.Document, *Diagnostic) {
	text, err := DecodeDocument(raw)
	if err != nil {
		return nil, &Diagnostic{Code: CodeParse, Message: err.Error()}
	}
	doc, err := policy.Parse(text, kind, limits)
	if err != nil {
		d := &Diagnostic{Code: CodeParse, Message: err.Error()}
		var pe *policy.ParseError
		if errors.As(err, &pe) {
			d.Path = pe.Path
		}
		return nil, d
	}
	return doc, nil
}

// DecodeDocument returns the JSON text of a policy document as found in
// authorization details: a JSON object (AWS CLI, which decodes for you), a
// JSON string holding the policy, or a URL-encoded string (RFC 3986, as the
// API and SDKs return it). Percent-decoding uses url.PathUnescape, which,
// unlike QueryUnescape, does not turn '+' into a space.
func DecodeDocument(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("policy document is missing")
	}
	switch trimmed[0] {
	case '{':
		return trimmed, nil
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil, fmt.Errorf("policy document string: %w", err)
		}
		if strings.HasPrefix(strings.TrimSpace(s), "{") {
			return []byte(s), nil
		}
		decoded, err := url.PathUnescape(s)
		if err != nil {
			return nil, fmt.Errorf("policy document is not valid URL encoding: %w", err)
		}
		return []byte(decoded), nil
	default:
		return nil, errors.New("policy document must be an object or a string")
	}
}
