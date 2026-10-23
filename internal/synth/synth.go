// Package synth generates realistic synthetic IAM snapshots from a seed:
// users, groups and roles spread over teams and paths, tags, service and
// cross-account trust, GitHub Actions OIDC trust, a few administrators and
// a configurable share of planted escalation paths. The same options always
// produce the same bytes. Used for benchmarks, the redaction property test
// and `escalint synth`.
package synth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
)

// Options controls generation.
type Options struct {
	Principals int    // users + groups + roles per account (default 50)
	Accounts   int    // 1..9 (default 1)
	Seed       uint64 // PRNG seed
	// EscalationRate is the share of principals that get a planted
	// escalation primitive (default 0.1, 0 plants none when NoEscalations).
	EscalationRate float64
	NoEscalations  bool
	// RandomNames uses random identifiers instead of word-based names
	// (redaction tests look for every identifier in the output).
	RandomNames bool
}

// Result is the generated snapshot and every identifier it contains.
type Result struct {
	JSON []byte
	// Identifiers are the account IDs, names, ARNs, paths, tag keys and
	// values, policy names and statement IDs the snapshot contains.
	Identifiers []string
}

// ErrOptions reports invalid options.
var ErrOptions = errors.New("synth: invalid options")

var (
	teams    = []string{"payments", "platform", "data", "identity", "search", "mobile", "billing", "growth", "infra", "security"}
	firsts   = []string{"alice", "bruno", "carla", "diego", "erin", "fatima", "gabriel", "hana", "igor", "julia", "kenji", "lucia", "marco", "nadia", "otto", "paula"}
	lasts    = []string{"silva", "smith", "tanaka", "costa", "mueller", "rossi", "garcia", "kim", "novak", "okafor"}
	services = []string{"api", "worker", "etl", "deploy", "reporting", "ingest", "scheduler", "gateway"}
	envs     = []string{"dev", "staging", "prod"}
	trusted  = []string{"lambda.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com", "codebuild.amazonaws.com", "glue.amazonaws.com"}
)

// Generate builds a snapshot envelope.
func Generate(opts Options) (*Result, error) {
	if opts.Principals == 0 {
		opts.Principals = 50
	}
	if opts.Accounts == 0 {
		opts.Accounts = 1
	}
	if opts.EscalationRate == 0 && !opts.NoEscalations {
		opts.EscalationRate = 0.1
	}
	if opts.Principals < 4 || opts.Principals > 100_000 || opts.Accounts < 1 || opts.Accounts > 9 || opts.EscalationRate < 0 || opts.EscalationRate > 1 {
		return nil, fmt.Errorf("%w: principals 4..100000, accounts 1..9, escalation rate 0..1", ErrOptions)
	}
	// #nosec G404 -- reproducible synthetic data, not a secret
	g := &gen{opts: opts, rng: rand.New(rand.NewPCG(opts.Seed, 0x9e3779b97f4a7c15)), used: map[string]bool{}}
	return g.run()
}

type gen struct {
	opts  Options
	rng   *rand.Rand
	used  map[string]bool
	ids   []string
	accts []string
}

func (g *gen) pick(list []string) string { return list[g.rng.IntN(len(list))] }

func (g *gen) note(s ...string) {
	for _, x := range s {
		if x != "" && x != "/" {
			g.ids = append(g.ids, x)
		}
	}
}

// randomWord is [g-z]{8} plus digits: never a hex string and never an
// English word, so a redaction test can search for it.
func (g *gen) randomWord() string {
	var b strings.Builder
	for range 8 {
		b.WriteByte("ghijklmnopqrstuvwxyz"[g.rng.IntN(20)])
	}
	return b.String()
}

// unique returns base, or base with a numeric suffix, never repeated.
func (g *gen) unique(base string) string {
	name := base
	for i := 2; g.used[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	g.used[name] = true
	return name
}

func (g *gen) name(kind string) string {
	if g.opts.RandomNames {
		return g.unique(kind + g.randomWord())
	}
	switch kind {
	case "user":
		return g.unique(g.pick(firsts) + "." + g.pick(lasts))
	case "group":
		return g.unique(g.pick(teams) + "-" + g.pick([]string{"developers", "operators", "readers", "oncall"}))
	case "policy":
		return g.unique(g.pick(teams) + "-" + g.pick([]string{"read", "deploy", "operate", "data-access", "ci"}))
	default:
		return g.unique(g.pick(teams) + "-" + g.pick(services) + "-" + g.pick(envs))
	}
}

func (g *gen) account() string {
	for {
		id := fmt.Sprintf("%012d", 100_000_000_000+g.rng.Int64N(900_000_000_000))
		if !g.used[id] {
			g.used[id] = true
			return id
		}
	}
}

func (g *gen) path() string {
	switch g.rng.IntN(4) {
	case 0, 1:
		return "/"
	case 2:
		if g.opts.RandomNames {
			return "/" + g.unique("path"+g.randomWord()) + "/"
		}
		return "/teams/" + g.pick(teams) + "/"
	default:
		if g.opts.RandomNames {
			return "/" + g.unique("path"+g.randomWord()) + "/"
		}
		return "/service/"
	}
}

func (g *gen) tags(owner string) []tag {
	if g.rng.IntN(3) == 0 {
		return []tag{}
	}
	if g.opts.RandomNames {
		k, v := g.unique("tag"+g.randomWord()), g.unique("val"+g.randomWord())
		g.note(k, v)
		return []tag{{Key: k, Value: v}}
	}
	return []tag{{Key: "team", Value: g.pick(teams)}, {Key: "env", Value: g.pick(envs)}, {Key: "owner", Value: owner}}
}

func (g *gen) sid() string {
	if g.opts.RandomNames {
		s := g.unique("Sid" + g.randomWord())
		g.note(s)
		return s
	}
	return ""
}

// ---- wire types (the escalint envelope, docs/research.md §8) -----------

type tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type doc struct {
	Version   string `json:"Version"`
	Statement []stmt `json:"Statement"`
}

type stmt struct {
	Sid       string         `json:"Sid,omitempty"`
	Effect    string         `json:"Effect"`
	Principal map[string]any `json:"Principal,omitempty"`
	Action    []string       `json:"Action"`
	Resource  []string       `json:"Resource,omitempty"`
	Condition map[string]any `json:"Condition,omitempty"`
}

type inline struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument doc    `json:"PolicyDocument"`
}

type attached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type user struct {
	Path                    string     `json:"Path"`
	UserName                string     `json:"UserName"`
	UserID                  string     `json:"UserId"`
	Arn                     string     `json:"Arn"`
	UserPolicyList          []inline   `json:"UserPolicyList"`
	GroupList               []string   `json:"GroupList"`
	AttachedManagedPolicies []attached `json:"AttachedManagedPolicies"`
	Tags                    []tag      `json:"Tags"`
}

type group struct {
	Path                    string     `json:"Path"`
	GroupName               string     `json:"GroupName"`
	GroupID                 string     `json:"GroupId"`
	Arn                     string     `json:"Arn"`
	GroupPolicyList         []inline   `json:"GroupPolicyList"`
	AttachedManagedPolicies []attached `json:"AttachedManagedPolicies"`
}

type lastUsed struct {
	LastUsedDate string `json:"LastUsedDate"`
	Region       string `json:"Region"`
}

type role struct {
	Path                     string     `json:"Path"`
	RoleName                 string     `json:"RoleName"`
	RoleID                   string     `json:"RoleId"`
	Arn                      string     `json:"Arn"`
	AssumeRolePolicyDocument doc        `json:"AssumeRolePolicyDocument"`
	RolePolicyList           []inline   `json:"RolePolicyList"`
	AttachedManagedPolicies  []attached `json:"AttachedManagedPolicies"`
	Tags                     []tag      `json:"Tags"`
	RoleLastUsed             *lastUsed  `json:"RoleLastUsed,omitempty"`
}

type version struct {
	Document         doc    `json:"Document"`
	VersionID        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
}

type managed struct {
	PolicyName        string    `json:"PolicyName"`
	PolicyID          string    `json:"PolicyId"`
	Arn               string    `json:"Arn"`
	Path              string    `json:"Path"`
	DefaultVersionID  string    `json:"DefaultVersionId"`
	PolicyVersionList []version `json:"PolicyVersionList"`
}

type authz struct {
	UserDetailList  []user    `json:"UserDetailList"`
	GroupDetailList []group   `json:"GroupDetailList"`
	RoleDetailList  []role    `json:"RoleDetailList"`
	Policies        []managed `json:"Policies"`
}

type oidc struct {
	Arn       string   `json:"arn"`
	URL       string   `json:"url"`
	ClientIDs []string `json:"client_ids"`
}

type account struct {
	AccountID            string `json:"account_id"`
	AuthorizationDetails authz  `json:"authorization_details"`
	IdentityProviders    struct {
		OIDC []oidc `json:"oidc"`
		SAML []any  `json:"saml"`
	} `json:"identity_providers"`
}

type envelope struct {
	Version     string `json:"escalint_snapshot"`
	CollectedAt string `json:"collected_at"`
	Collector   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"collector"`
	Partition string    `json:"partition"`
	Accounts  []account `json:"accounts"`
}

const policyVersion = "2012-10-17"

func allow(sid string, actions []string, resources ...string) stmt {
	return stmt{Sid: sid, Effect: "Allow", Action: actions, Resource: resources}
}

func (g *gen) uid(prefix string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var b strings.Builder
	b.WriteString(prefix)
	for range 17 {
		b.WriteByte(alphabet[g.rng.IntN(len(alphabet))])
	}
	return b.String()
}

func (g *gen) run() (*Result, error) {
	env := envelope{Version: "1", CollectedAt: "2026-10-01T00:00:00Z", Partition: "aws"}
	env.Collector.Name, env.Collector.Version = "escalint-synth", "1"
	for range g.opts.Accounts {
		g.accts = append(g.accts, g.account())
	}
	g.note(g.accts...)
	vendor := g.account()
	g.note(vendor)
	for i, id := range g.accts {
		env.Accounts = append(env.Accounts, g.accountData(id, i, vendor))
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	ids := slices.Clone(g.ids)
	slices.Sort(ids)
	return &Result{JSON: append(data, '\n'), Identifiers: slices.Compact(ids)}, nil
}

func (g *gen) accountData(id string, index int, vendor string) account {
	iam := "arn:aws:iam::" + id + ":"
	a := account{AccountID: id}
	a.IdentityProviders.SAML = []any{}
	az := &a.AuthorizationDetails
	gh := iam + "oidc-provider/token.actions.githubusercontent.com"
	a.IdentityProviders.OIDC = []oidc{{Arn: gh, URL: "https://token.actions.githubusercontent.com", ClientIDs: []string{"sts.amazonaws.com"}}}

	nGroups := max(1, g.opts.Principals/10)
	nRoles := g.opts.Principals * 5 / 10
	nUsers := g.opts.Principals - nGroups - nRoles

	// Customer managed policies.
	policies := make([]string, 0, max(3, g.opts.Principals/15))
	for range max(3, g.opts.Principals/15) {
		name, path := g.name("policy"), g.path()
		arn := iam + "policy" + path + name
		g.note(name, arn, path)
		team := g.pick(teams)
		d := doc{Version: policyVersion, Statement: []stmt{
			allow(g.sid(), []string{"s3:GetObject", "s3:ListBucket"}, "arn:aws:s3:::"+team+"-*"),
			allow(g.sid(), []string{"logs:CreateLogStream", "logs:PutLogEvents", "cloudwatch:PutMetricData"}, "*"),
		}}
		az.Policies = append(az.Policies, managed{
			PolicyName: name, PolicyID: g.uid("ANPA"), Arn: arn, Path: path, DefaultVersionID: "v1",
			PolicyVersionList: []version{{Document: d, VersionID: "v1", IsDefaultVersion: true}},
		})
		policies = append(policies, arn)
	}
	// The AWS managed policy some principals attach (authorization details
	// include every attached AWS managed policy).
	az.Policies = append(az.Policies, managed{
		PolicyName: "ReadOnlyAccess", PolicyID: "ANPAILL3HVNFSB6DCOWYQ", Arn: "arn:aws:iam::aws:policy/ReadOnlyAccess", Path: "/", DefaultVersionID: "v1",
		PolicyVersionList: []version{{VersionID: "v1", IsDefaultVersion: true, Document: doc{Version: policyVersion, Statement: []stmt{
			allow("", []string{"ec2:Describe*", "iam:Get*", "iam:List*", "s3:List*", "cloudwatch:Get*"}, "*"),
		}}}},
	})
	attach := func() []attached {
		out := []attached{}
		if g.rng.IntN(2) == 0 {
			arn := g.pick(policies)
			out = append(out, attached{PolicyName: arn[strings.LastIndex(arn, "/")+1:], PolicyArn: arn})
		}
		if g.rng.IntN(4) == 0 {
			out = append(out, attached{PolicyName: "ReadOnlyAccess", PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess"})
		}
		return out
	}
	inlineFor := func(owner string) []inline {
		if g.rng.IntN(3) != 0 {
			return []inline{}
		}
		name := g.unique("inline-" + g.pick(services))
		if g.opts.RandomNames {
			name = g.unique("pol" + g.randomWord())
		}
		g.note(name)
		return []inline{{PolicyName: name, PolicyDocument: doc{Version: policyVersion, Statement: []stmt{
			allow(g.sid(), []string{"dynamodb:GetItem", "dynamodb:Query"}, "arn:aws:dynamodb:us-east-1:"+id+":table/"+owner+"*"),
		}}}}
	}

	groupNames := make([]string, 0, nGroups)
	for range nGroups {
		name, path := g.name("group"), g.path()
		arn := iam + "group" + path + name
		g.note(name, arn, path)
		az.GroupDetailList = append(az.GroupDetailList, group{
			Path: path, GroupName: name, GroupID: g.uid("AGPA"), Arn: arn,
			GroupPolicyList: inlineFor(name), AttachedManagedPolicies: attach(),
		})
		groupNames = append(groupNames, name)
	}

	type principal struct {
		arn    string
		isRole bool
		user   *user
		role   *role
	}
	all := make([]principal, 0, nUsers+nRoles)
	for range nUsers {
		name, path := g.name("user"), g.path()
		arn := iam + "user" + path + name
		g.note(name, arn, path)
		u := user{
			Path: path, UserName: name, UserID: g.uid("AIDA"), Arn: arn, UserPolicyList: inlineFor(name),
			GroupList: []string{}, AttachedManagedPolicies: attach(), Tags: g.tags(name),
		}
		for _, t := range u.Tags {
			g.note(t.Value)
		}
		if g.rng.IntN(3) > 0 {
			u.GroupList = append(u.GroupList, g.pick(groupNames))
		}
		az.UserDetailList = append(az.UserDetailList, u)
	}
	for i := range nRoles {
		name, path := g.name("role"), g.path()
		arn := iam + "role" + path + name
		g.note(name, arn, path)
		r := role{
			Path: path, RoleName: name, RoleID: g.uid("AROA"), Arn: arn, RolePolicyList: inlineFor(name),
			AttachedManagedPolicies: attach(), Tags: g.tags(name),
		}
		for _, t := range r.Tags {
			g.note(t.Value)
		}
		r.AssumeRolePolicyDocument = g.trust(id, index, i, vendor, gh)
		if g.rng.IntN(2) == 0 {
			r.RoleLastUsed = &lastUsed{LastUsedDate: fmt.Sprintf("2026-%02d-15T00:00:00Z", 1+g.rng.IntN(9)), Region: "us-east-1"}
		}
		az.RoleDetailList = append(az.RoleDetailList, r)
	}
	for i := range az.UserDetailList {
		all = append(all, principal{arn: az.UserDetailList[i].Arn, user: &az.UserDetailList[i]})
	}
	for i := range az.RoleDetailList {
		all = append(all, principal{arn: az.RoleDetailList[i].Arn, isRole: true, role: &az.RoleDetailList[i]})
	}

	// Administrators: one role and one user, the escalation targets.
	admin := stmt{Sid: g.sid(), Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}}
	adminRole := &az.RoleDetailList[0]
	adminRole.RolePolicyList = append(adminRole.RolePolicyList, inline{PolicyName: g.adminName(), PolicyDocument: doc{Version: policyVersion, Statement: []stmt{admin}}})
	adminRole.AssumeRolePolicyDocument = doc{Version: policyVersion, Statement: []stmt{{Effect: "Allow", Principal: map[string]any{"Service": "lambda.amazonaws.com"}, Action: []string{"sts:AssumeRole"}}}}
	adminUser := adminRole.Arn
	if len(az.UserDetailList) > 0 {
		u := &az.UserDetailList[0]
		u.UserPolicyList = append(u.UserPolicyList, inline{PolicyName: g.adminName(), PolicyDocument: doc{Version: policyVersion, Statement: []stmt{admin}}})
		adminUser = u.Arn
	}

	// Planted escalations.
	planted := int(float64(len(all)) * g.opts.EscalationRate)
	for i := 0; i < planted && len(all) > 2; i++ {
		p := all[1+g.rng.IntN(len(all)-1)]
		st := g.escalation(id, adminRole.Arn, adminUser, p.arn, policies)
		pol := inline{PolicyName: g.unique("escalation-" + g.pick(services)), PolicyDocument: doc{Version: policyVersion, Statement: st}}
		if g.opts.RandomNames {
			pol.PolicyName = g.unique("esc" + g.randomWord())
		}
		g.note(pol.PolicyName)
		if p.isRole {
			p.role.RolePolicyList = append(p.role.RolePolicyList, pol)
		} else {
			p.user.UserPolicyList = append(p.user.UserPolicyList, pol)
		}
	}
	return a
}

func (g *gen) adminName() string {
	if g.opts.RandomNames {
		n := g.unique("adm" + g.randomWord())
		g.note(n)
		return n
	}
	return g.unique("administrator")
}

func (g *gen) trust(id string, index, i int, vendor, githubProvider string) doc {
	d := doc{Version: policyVersion}
	switch g.rng.IntN(10) {
	case 0, 1, 2, 3:
		d.Statement = []stmt{{Effect: "Allow", Principal: map[string]any{"Service": g.pick(trusted)}, Action: []string{"sts:AssumeRole"}}}
	case 4, 5:
		d.Statement = []stmt{{Effect: "Allow", Principal: map[string]any{"AWS": "arn:aws:iam::" + id + ":root"}, Action: []string{"sts:AssumeRole"}}}
	case 6:
		other := g.accts[(index+1)%len(g.accts)]
		d.Statement = []stmt{{Effect: "Allow", Principal: map[string]any{"AWS": "arn:aws:iam::" + other + ":root"}, Action: []string{"sts:AssumeRole"}}}
	case 7:
		d.Statement = []stmt{{
			Effect: "Allow", Principal: map[string]any{"AWS": "arn:aws:iam::" + vendor + ":root"}, Action: []string{"sts:AssumeRole"},
			Condition: map[string]any{"StringEquals": map[string]any{"sts:ExternalId": fmt.Sprintf("ext-%d-%d", index, i)}},
		}}
	case 8:
		repo := "repo:" + g.pick(teams) + "/" + g.pick(services) + ":ref:refs/heads/main"
		if g.opts.RandomNames {
			repo = "repo:" + g.unique("org"+g.randomWord()) + "/app:ref:refs/heads/main"
			g.note(repo)
		}
		d.Statement = []stmt{{
			Effect: "Allow", Principal: map[string]any{"Federated": githubProvider}, Action: []string{"sts:AssumeRoleWithWebIdentity"},
			Condition: map[string]any{"StringEquals": map[string]any{ // #nosec G101 -- condition keys, not credentials
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": repo,
			}},
		}}
	default:
		d.Statement = []stmt{{Effect: "Allow", Principal: map[string]any{"Service": "ec2.amazonaws.com"}, Action: []string{"sts:AssumeRole"}}}
	}
	return d
}

// escalation returns statements granting one escalation primitive. Grants
// on every user (`user/*`) are rare: each one adds an edge to every user of
// the account, which real accounts seldom have at scale.
func (g *gen) escalation(id, adminRole, adminUser, self string, policies []string) []stmt {
	iam := "arn:aws:iam::" + id + ":"
	switch g.rng.IntN(6) {
	case 0:
		return []stmt{allow(g.sid(), []string{"iam:PassRole"}, adminRole), allow(g.sid(), []string{"lambda:CreateFunction", "lambda:InvokeFunction"}, "*")}
	case 1:
		return []stmt{allow(g.sid(), []string{"iam:CreatePolicyVersion"}, g.pick(policies)), allow(g.sid(), []string{"iam:CreatePolicyVersion"}, iam+"policy/*")}
	case 2:
		if strings.Contains(self, ":user/") {
			return []stmt{allow(g.sid(), []string{"iam:AttachUserPolicy"}, self)}
		}
		return []stmt{allow(g.sid(), []string{"iam:AttachRolePolicy"}, self)}
	case 3:
		return []stmt{allow(g.sid(), []string{"iam:UpdateAssumeRolePolicy"}, adminRole), allow(g.sid(), []string{"sts:AssumeRole"}, adminRole)}
	case 4:
		if g.rng.IntN(20) == 0 {
			return []stmt{allow(g.sid(), []string{"iam:CreateAccessKey"}, iam+"user/*")}
		}
		return []stmt{allow(g.sid(), []string{"iam:CreateAccessKey"}, adminUser)}
	default:
		return []stmt{allow(g.sid(), []string{"iam:PutRolePolicy"}, iam+"role/*")}
	}
}
