// Package collect builds an escalint snapshot from an AWS account with
// read-only calls (docs/research.md §10). Every AWS call goes through the
// small interfaces below, so tests use fakes and a test checks that the
// documented collector policy (docs/collector-policy.json) matches exactly
// the operations used here.
package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSAPI identifies the caller and, with --assume-roles, switches accounts.
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// IAMAPI reads users, groups, roles, policies and identity providers.
type IAMAPI interface {
	GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput, opts ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	ListOpenIDConnectProviders(ctx context.Context, in *iam.ListOpenIDConnectProvidersInput, opts ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error)
	GetOpenIDConnectProvider(ctx context.Context, in *iam.GetOpenIDConnectProviderInput, opts ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error)
	ListSAMLProviders(ctx context.Context, in *iam.ListSAMLProvidersInput, opts ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error)
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetLoginProfile(ctx context.Context, in *iam.GetLoginProfileInput, opts ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
}

// OrganizationsAPI reads the organization tree and its SCPs and RCPs
// (--org; management or delegated administrator account).
type OrganizationsAPI interface {
	DescribeOrganization(ctx context.Context, in *organizations.DescribeOrganizationInput, opts ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(ctx context.Context, in *organizations.ListRootsInput, opts ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(ctx context.Context, in *organizations.ListOrganizationalUnitsForParentInput, opts ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(ctx context.Context, in *organizations.ListAccountsForParentInput, opts ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	ListPolicies(ctx context.Context, in *organizations.ListPoliciesInput, opts ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(ctx context.Context, in *organizations.DescribePolicyInput, opts ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(ctx context.Context, in *organizations.ListTargetsForPolicyInput, opts ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

// LambdaAPI lists functions and their execution roles (--resources lambda).
type LambdaAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, opts ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

// EC2API lists instances and their instance profiles (--resources ec2).
type EC2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// SSMAPI tells which instances are managed by Systems Manager (--resources ec2).
type SSMAPI interface {
	DescribeInstanceInformation(ctx context.Context, in *ssm.DescribeInstanceInformationInput, opts ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
}

// CodeBuildAPI lists projects and their service roles (--resources codebuild).
type CodeBuildAPI interface {
	ListProjects(ctx context.Context, in *codebuild.ListProjectsInput, opts ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, in *codebuild.BatchGetProjectsInput, opts ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

// Regional clients for one region of the resource inventory.
type Regional struct {
	Region    string
	Lambda    LambdaAPI
	EC2       EC2API
	SSM       SSMAPI
	CodeBuild CodeBuildAPI
}

// Clients are the clients of one account.
type Clients struct {
	STS           STSAPI
	IAM           IAMAPI
	Organizations OrganizationsAPI // nil unless --org
	Regions       []Regional       // empty unless --resources
}
