package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/brennocm/escalint/internal/arn"
)

// Options controls a collection.
type Options struct {
	// Concurrency bounds the per-user calls (access keys, login profiles).
	Concurrency int
	// Extras collects access key counts and login profiles (default on in
	// the CLI; off only for very large accounts).
	Extras bool
	// Log receives progress lines; nil discards them.
	Log io.Writer
	// Now is the collection time (tests pin it).
	Now func() time.Time
	// Version is written in the envelope's collector block.
	Version string
}

// Resource types of the inventory.
const (
	ResourceLambda    = "lambda"
	ResourceEC2       = "ec2"
	ResourceCodeBuild = "codebuild"
)

// ErrNoAccount is returned when the caller identity has no account.
var ErrNoAccount = errors.New("collect: caller identity has no account")

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, format+"\n", args...)
	}
}

// Identity returns the caller's account and partition.
func Identity(ctx context.Context, s STSAPI) (account, partition string, err error) {
	out, err := s.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	account = aws.ToString(out.Account)
	if account == "" {
		return "", "", ErrNoAccount
	}
	partition = "aws"
	if a, err := arn.Parse(aws.ToString(out.Arn)); err == nil {
		partition = a.Partition
	}
	return account, partition, nil
}

// Assume returns short-lived credentials for a role (--assume-roles). The
// session lasts 15 minutes, the minimum STS allows.
func Assume(ctx context.Context, s STSAPI, roleARN string) (*ststypes.Credentials, error) {
	out, err := s.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: aws.String(roleARN), RoleSessionName: aws.String("escalint-collect"), DurationSeconds: aws.Int32(900),
	})
	if err != nil {
		return nil, fmt.Errorf("sts:AssumeRole %s: %w", roleARN, err)
	}
	return out.Credentials, nil
}

// ReadAccount collects one account.
func ReadAccount(ctx context.Context, c Clients, account, partition string, opts Options) (*Account, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	a := &Account{AccountID: account}
	if err := authorizationDetails(ctx, c.IAM, &a.AuthorizationDetails, opts); err != nil {
		return nil, err
	}
	if err := identityProviders(ctx, c.IAM, &a.IdentityProviders); err != nil {
		return nil, err
	}
	if opts.Extras {
		ex, err := extras(ctx, c.IAM, a.AuthorizationDetails.UserDetailList, opts)
		if err != nil {
			return nil, err
		}
		a.Extras = ex
	}
	if len(c.Regions) > 0 {
		inv, err := inventory(ctx, c.Regions, account, partition, opts)
		if err != nil {
			return nil, err
		}
		a.Resources = inv
	}
	return a, nil
}

func authorizationDetails(ctx context.Context, api IAMAPI, out *AuthzDetails, opts Options) error {
	out.UserDetailList, out.GroupDetailList, out.RoleDetailList, out.Policies = []User{}, []Group{}, []Role{}, []Managed{}
	p := iam.NewGetAccountAuthorizationDetailsPaginator(api, &iam.GetAccountAuthorizationDetailsInput{})
	pages := 0
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("iam:GetAccountAuthorizationDetails: %w", err)
		}
		pages++
		for _, u := range page.UserDetailList {
			out.UserDetailList = append(out.UserDetailList, user(u))
		}
		for _, g := range page.GroupDetailList {
			out.GroupDetailList = append(out.GroupDetailList, Group{
				Path: aws.ToString(g.Path), GroupName: aws.ToString(g.GroupName), GroupID: aws.ToString(g.GroupId), Arn: aws.ToString(g.Arn),
				GroupPolicyList: inlines(g.GroupPolicyList), AttachedManagedPolicies: attached(g.AttachedManagedPolicies),
			})
		}
		for _, r := range page.RoleDetailList {
			out.RoleDetailList = append(out.RoleDetailList, role(r))
		}
		for _, m := range page.Policies {
			mp := Managed{
				PolicyName: aws.ToString(m.PolicyName), PolicyID: aws.ToString(m.PolicyId), Arn: aws.ToString(m.Arn),
				Path: aws.ToString(m.Path), DefaultVersionID: aws.ToString(m.DefaultVersionId), PolicyVersionList: []Version{},
			}
			for _, v := range m.PolicyVersionList {
				mp.PolicyVersionList = append(mp.PolicyVersionList, Version{Document: decodeDocument(v.Document), VersionID: aws.ToString(v.VersionId), IsDefaultVersion: v.IsDefaultVersion})
			}
			out.Policies = append(out.Policies, mp)
		}
	}
	opts.logf("authorization details: %d users, %d groups, %d roles, %d policies (%d pages)",
		len(out.UserDetailList), len(out.GroupDetailList), len(out.RoleDetailList), len(out.Policies), pages)
	return nil
}

func user(u iamtypes.UserDetail) User {
	return User{
		Path: aws.ToString(u.Path), UserName: aws.ToString(u.UserName), UserID: aws.ToString(u.UserId), Arn: aws.ToString(u.Arn),
		CreateDate: timeString(u.CreateDate), UserPolicyList: inlines(u.UserPolicyList), GroupList: append([]string{}, u.GroupList...),
		AttachedManagedPolicies: attached(u.AttachedManagedPolicies), PermissionsBoundary: boundary(u.PermissionsBoundary), Tags: tags(u.Tags),
	}
}

func role(r iamtypes.RoleDetail) Role {
	out := Role{
		Path: aws.ToString(r.Path), RoleName: aws.ToString(r.RoleName), RoleID: aws.ToString(r.RoleId), Arn: aws.ToString(r.Arn),
		AssumeRolePolicyDocument: decodeDocument(r.AssumeRolePolicyDocument), InstanceProfileList: []InstanceProfile{},
		RolePolicyList: inlines(r.RolePolicyList), AttachedManagedPolicies: attached(r.AttachedManagedPolicies),
		PermissionsBoundary: boundary(r.PermissionsBoundary), Tags: tags(r.Tags),
	}
	for _, ip := range r.InstanceProfileList {
		out.InstanceProfileList = append(out.InstanceProfileList, InstanceProfile{InstanceProfileName: aws.ToString(ip.InstanceProfileName), Arn: aws.ToString(ip.Arn)})
	}
	if lu := r.RoleLastUsed; lu != nil && lu.LastUsedDate != nil {
		out.RoleLastUsed = &LastUsed{LastUsedDate: timeString(lu.LastUsedDate), Region: aws.ToString(lu.Region)}
	}
	return out
}

func identityProviders(ctx context.Context, api IAMAPI, out *IdentityProviders) error {
	out.OIDC, out.SAML = []OIDCProvider{}, []SAMLProvider{}
	oidc, err := api.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return fmt.Errorf("iam:ListOpenIDConnectProviders: %w", err)
	}
	for _, p := range oidc.OpenIDConnectProviderList {
		d, err := api.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: p.Arn})
		if err != nil {
			return fmt.Errorf("iam:GetOpenIDConnectProvider: %w", err)
		}
		out.OIDC = append(out.OIDC, OIDCProvider{Arn: aws.ToString(p.Arn), URL: aws.ToString(d.Url), ClientIDs: append([]string{}, d.ClientIDList...)})
	}
	saml, err := api.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return fmt.Errorf("iam:ListSAMLProviders: %w", err)
	}
	for _, p := range saml.SAMLProviderList {
		out.SAML = append(out.SAML, SAMLProvider{Arn: aws.ToString(p.Arn)})
	}
	sort.Slice(out.OIDC, func(i, j int) bool { return out.OIDC[i].Arn < out.OIDC[j].Arn })
	sort.Slice(out.SAML, func(i, j int) bool { return out.SAML[i].Arn < out.SAML[j].Arn })
	return nil
}

// extras lists access key statuses and login profiles for every user, with
// bounded concurrency. Only key statuses are kept, never key IDs.
func extras(ctx context.Context, api IAMAPI, users []User, opts Options) (*Extras, error) {
	ex := &Extras{AccessKeys: map[string][]AccessKey{}, LoginProfiles: map[string]bool{}}
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for _, u := range users {
		wg.Add(1)
		sem <- struct{}{}
		go func(u User) {
			defer wg.Done()
			defer func() { <-sem }()
			keys, hasProfile, err := userExtras(ctx, api, u.UserName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			ex.AccessKeys[u.Arn] = keys
			ex.LoginProfiles[u.Arn] = hasProfile
		}(u)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	opts.logf("extras: access keys and login profiles of %d users", len(users))
	return ex, nil
}

func userExtras(ctx context.Context, api IAMAPI, name string) ([]AccessKey, bool, error) {
	keys := []AccessKey{}
	p := iam.NewListAccessKeysPaginator(api, &iam.ListAccessKeysInput{UserName: aws.String(name)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("iam:ListAccessKeys %s: %w", name, err)
		}
		for _, k := range page.AccessKeyMetadata {
			keys = append(keys, AccessKey{Status: string(k.Status)})
		}
	}
	_, err := api.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: aws.String(name)})
	var notFound *iamtypes.NoSuchEntityException
	switch {
	case errors.As(err, &notFound):
		return keys, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("iam:GetLoginProfile %s: %w", name, err)
	}
	return keys, true, nil
}

func inventory(ctx context.Context, regions []Regional, account, partition string, opts Options) (*ResourceInventory, error) {
	inv := &ResourceInventory{Lambda: []LambdaFunction{}, EC2: []EC2Instance{}, CodeBuild: []CodeBuild{}}
	for _, r := range regions {
		if r.Lambda != nil {
			p := lambda.NewListFunctionsPaginator(r.Lambda, &lambda.ListFunctionsInput{})
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("lambda:ListFunctions (%s): %w", r.Region, err)
				}
				for _, f := range page.Functions {
					inv.Lambda = append(inv.Lambda, LambdaFunction{Arn: aws.ToString(f.FunctionArn), Role: aws.ToString(f.Role)})
				}
			}
		}
		if r.EC2 != nil {
			managed := map[string]bool{}
			if r.SSM != nil {
				p := ssm.NewDescribeInstanceInformationPaginator(r.SSM, &ssm.DescribeInstanceInformationInput{})
				for p.HasMorePages() {
					page, err := p.NextPage(ctx)
					if err != nil {
						return nil, fmt.Errorf("ssm:DescribeInstanceInformation (%s): %w", r.Region, err)
					}
					for _, i := range page.InstanceInformationList {
						managed[aws.ToString(i.InstanceId)] = true
					}
				}
			}
			p := ec2.NewDescribeInstancesPaginator(r.EC2, &ec2.DescribeInstancesInput{})
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ec2:DescribeInstances (%s): %w", r.Region, err)
				}
				for _, res := range page.Reservations {
					for _, i := range res.Instances {
						id := aws.ToString(i.InstanceId)
						profile := ""
						if i.IamInstanceProfile != nil {
							profile = aws.ToString(i.IamInstanceProfile.Arn)
						}
						inv.EC2 = append(inv.EC2, EC2Instance{
							Arn: fmt.Sprintf("arn:%s:ec2:%s:%s:instance/%s", partition, r.Region, account, id), InstanceProfile: profile, SSMManaged: managed[id],
						})
					}
				}
			}
		}
		if r.CodeBuild != nil {
			var names []string
			p := codebuild.NewListProjectsPaginator(r.CodeBuild, &codebuild.ListProjectsInput{})
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("codebuild:ListProjects (%s): %w", r.Region, err)
				}
				names = append(names, page.Projects...)
			}
			for start := 0; start < len(names); start += 100 {
				end := min(start+100, len(names))
				out, err := r.CodeBuild.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: names[start:end]})
				if err != nil {
					return nil, fmt.Errorf("codebuild:BatchGetProjects (%s): %w", r.Region, err)
				}
				for _, pr := range out.Projects {
					inv.CodeBuild = append(inv.CodeBuild, CodeBuild{Arn: aws.ToString(pr.Arn), ServiceRole: aws.ToString(pr.ServiceRole)})
				}
			}
		}
	}
	sort.Slice(inv.Lambda, func(i, j int) bool { return inv.Lambda[i].Arn < inv.Lambda[j].Arn })
	sort.Slice(inv.EC2, func(i, j int) bool { return inv.EC2[i].Arn < inv.EC2[j].Arn })
	sort.Slice(inv.CodeBuild, func(i, j int) bool { return inv.CodeBuild[i].Arn < inv.CodeBuild[j].Arn })
	opts.logf("resources: %d functions, %d instances, %d projects", len(inv.Lambda), len(inv.EC2), len(inv.CodeBuild))
	return inv, nil
}

// ReadOrganization reads the organization tree and its SCPs and RCPs.
// Policy types that are not enabled are skipped.
func ReadOrganization(ctx context.Context, api OrganizationsAPI, opts Options) (*Organization, error) {
	desc, err := api.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return nil, fmt.Errorf("organizations:DescribeOrganization: %w", err)
	}
	org := &Organization{
		ID: aws.ToString(desc.Organization.Id), ManagementAccountID: aws.ToString(desc.Organization.MasterAccountId),
		Tree: []OrgNode{}, Policies: []OrgPolicy{},
	}
	rp := organizations.NewListRootsPaginator(api, &organizations.ListRootsInput{})
	var queue []string
	for rp.HasMorePages() {
		page, err := rp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("organizations:ListRoots: %w", err)
		}
		for _, r := range page.Roots {
			org.Tree = append(org.Tree, OrgNode{ID: aws.ToString(r.Id), Type: "ROOT"})
			queue = append(queue, aws.ToString(r.Id))
		}
	}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		parentRef := parent
		op := organizations.NewListOrganizationalUnitsForParentPaginator(api, &organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parent)})
		for op.HasMorePages() {
			page, err := op.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("organizations:ListOrganizationalUnitsForParent: %w", err)
			}
			for _, ou := range page.OrganizationalUnits {
				org.Tree = append(org.Tree, OrgNode{ID: aws.ToString(ou.Id), Type: "ORGANIZATIONAL_UNIT", Parent: &parentRef})
				queue = append(queue, aws.ToString(ou.Id))
			}
		}
		ap := organizations.NewListAccountsForParentPaginator(api, &organizations.ListAccountsForParentInput{ParentId: aws.String(parent)})
		for ap.HasMorePages() {
			page, err := ap.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("organizations:ListAccountsForParent: %w", err)
			}
			for _, acct := range page.Accounts {
				org.Tree = append(org.Tree, OrgNode{ID: aws.ToString(acct.Id), Type: "ACCOUNT", Parent: &parentRef})
			}
		}
	}
	for _, t := range []orgtypes.PolicyType{orgtypes.PolicyTypeServiceControlPolicy, orgtypes.PolicyTypeResourceControlPolicy} {
		pp := organizations.NewListPoliciesPaginator(api, &organizations.ListPoliciesInput{Filter: t})
		for pp.HasMorePages() {
			page, err := pp.NextPage(ctx)
			var disabled *orgtypes.PolicyTypeNotEnabledException
			if errors.As(err, &disabled) {
				opts.logf("organization: %s is not enabled", t)
				break
			}
			if err != nil {
				return nil, fmt.Errorf("organizations:ListPolicies %s: %w", t, err)
			}
			for _, s := range page.Policies {
				pol, err := orgPolicy(ctx, api, s, t)
				if err != nil {
					return nil, err
				}
				org.Policies = append(org.Policies, pol)
			}
		}
	}
	sort.Slice(org.Policies, func(i, j int) bool { return org.Policies[i].ID < org.Policies[j].ID })
	opts.logf("organization %s: %d nodes, %d policies", org.ID, len(org.Tree), len(org.Policies))
	return org, nil
}

func orgPolicy(ctx context.Context, api OrganizationsAPI, s orgtypes.PolicySummary, t orgtypes.PolicyType) (OrgPolicy, error) {
	d, err := api.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: s.Id})
	if err != nil {
		return OrgPolicy{}, fmt.Errorf("organizations:DescribePolicy: %w", err)
	}
	content := ""
	if d.Policy != nil {
		content = aws.ToString(d.Policy.Content)
	}
	pol := OrgPolicy{ID: aws.ToString(s.Id), Type: string(t), Name: aws.ToString(s.Name), Document: decodeDocument(&content), Targets: []string{}}
	tp := organizations.NewListTargetsForPolicyPaginator(api, &organizations.ListTargetsForPolicyInput{PolicyId: s.Id})
	for tp.HasMorePages() {
		page, err := tp.NextPage(ctx)
		if err != nil {
			return OrgPolicy{}, fmt.Errorf("organizations:ListTargetsForPolicy: %w", err)
		}
		for _, target := range page.Targets {
			pol.Targets = append(pol.Targets, aws.ToString(target.TargetId))
		}
	}
	sort.Strings(pol.Targets)
	return pol, nil
}

// NewEnvelope assembles the snapshot.
func NewEnvelope(partition string, accounts []*Account, org *Organization, opts Options) *Envelope {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	env := &Envelope{
		Version: "1", CollectedAt: now().UTC().Format(time.RFC3339),
		Collector: Collector{Name: "escalint", Version: opts.Version}, Partition: partition, Org: org,
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].AccountID < accounts[j].AccountID })
	for _, a := range accounts {
		env.Accounts = append(env.Accounts, *a)
	}
	return env
}

// ParseResources validates a --resources list.
func ParseResources(list []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, r := range list {
		switch r = strings.TrimSpace(strings.ToLower(r)); r {
		case ResourceLambda, ResourceEC2, ResourceCodeBuild:
			out[r] = true
		case "":
		default:
			return nil, fmt.Errorf("unknown resource type %q (want lambda, ec2, codebuild)", r)
		}
	}
	return out, nil
}
