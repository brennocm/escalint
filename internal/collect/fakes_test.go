package collect

import (
	"context"
	"errors"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

const acct = "111111111111"

func enc(doc string) *string { return aws.String(url.PathEscape(doc)) }

type fakeSTS struct{ assumed []string }

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(acct), Arn: aws.String("arn:aws:iam::" + acct + ":user/collector")}, nil
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.assumed = append(f.assumed, aws.ToString(in.RoleArn))
	if aws.ToInt32(in.DurationSeconds) != 900 || aws.ToString(in.RoleSessionName) != "escalint-collect" {
		return nil, errors.New("unexpected session parameters")
	}
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE")}}, nil
}

type fakeIAM struct {
	failExtras bool
}

func (f *fakeIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	iamARN := "arn:aws:iam::" + acct + ":"
	if in.Marker == nil {
		return &iam.GetAccountAuthorizationDetailsOutput{
			IsTruncated: true, Marker: aws.String("page2"),
			UserDetailList: []iamtypes.UserDetail{{
				UserName: aws.String("alice"), UserId: aws.String("AIDAALICE"), Arn: aws.String(iamARN + "user/alice"), Path: aws.String("/"),
				GroupList: []string{"devs"},
				UserPolicyList: []iamtypes.PolicyDetail{{PolicyName: aws.String("keys"), PolicyDocument: enc(
					`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}`)}},
				PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(iamARN + "policy/Boundary"), PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentTypePolicy},
				Tags:                []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("a+b")}},
			}, {
				UserName: aws.String("bob"), UserId: aws.String("AIDABOB"), Arn: aws.String(iamARN + "user/bob"), Path: aws.String("/"),
			}},
			GroupDetailList: []iamtypes.GroupDetail{{GroupName: aws.String("devs"), GroupId: aws.String("AGPADEVS"), Arn: aws.String(iamARN + "group/devs"), Path: aws.String("/")}},
		}, nil
	}
	return &iam.GetAccountAuthorizationDetailsOutput{
		RoleDetailList: []iamtypes.RoleDetail{{
			RoleName: aws.String("admin"), RoleId: aws.String("AROAADMIN"), Arn: aws.String(iamARN + "role/admin"), Path: aws.String("/"),
			AssumeRolePolicyDocument: enc(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			AttachedManagedPolicies:  []iamtypes.AttachedPolicy{{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")}},
			InstanceProfileList:      []iamtypes.InstanceProfile{{InstanceProfileName: aws.String("admin"), Arn: aws.String(iamARN + "instance-profile/admin")}},
			RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: aws.Time(fixedNow()), Region: aws.String("us-east-1")},
		}},
		Policies: []iamtypes.ManagedPolicyDetail{{
			PolicyName: aws.String("AdministratorAccess"), Arn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"), Path: aws.String("/"),
			DefaultVersionId: aws.String("v1"),
			PolicyVersionList: []iamtypes.PolicyVersion{{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: enc(
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}},
		}, {
			PolicyName: aws.String("Boundary"), Arn: aws.String(iamARN + "policy/Boundary"), Path: aws.String("/"), DefaultVersionId: aws.String("v1"),
			PolicyVersionList: []iamtypes.PolicyVersion{{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: aws.String("not%20json")}},
		}},
	}, nil
}

func (f *fakeIAM) ListOpenIDConnectProviders(context.Context, *iam.ListOpenIDConnectProvidersInput, ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	return &iam.ListOpenIDConnectProvidersOutput{OpenIDConnectProviderList: []iamtypes.OpenIDConnectProviderListEntry{
		{Arn: aws.String("arn:aws:iam::" + acct + ":oidc-provider/token.actions.githubusercontent.com")},
	}}, nil
}

func (f *fakeIAM) GetOpenIDConnectProvider(context.Context, *iam.GetOpenIDConnectProviderInput, ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error) {
	return &iam.GetOpenIDConnectProviderOutput{Url: aws.String("token.actions.githubusercontent.com"), ClientIDList: []string{"sts.amazonaws.com"}}, nil
}

func (f *fakeIAM) ListSAMLProviders(context.Context, *iam.ListSAMLProvidersInput, ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error) {
	return &iam.ListSAMLProvidersOutput{SAMLProviderList: []iamtypes.SAMLProviderListEntry{{Arn: aws.String("arn:aws:iam::" + acct + ":saml-provider/corp")}}}, nil
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if f.failExtras {
		return nil, errors.New("AccessDenied")
	}
	if aws.ToString(in.UserName) == "alice" {
		return &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{{Status: iamtypes.StatusTypeActive}, {Status: iamtypes.StatusTypeInactive}}}, nil
	}
	return &iam.ListAccessKeysOutput{}, nil
}

func (f *fakeIAM) GetLoginProfile(_ context.Context, in *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	if aws.ToString(in.UserName) == "alice" {
		return &iam.GetLoginProfileOutput{}, nil
	}
	return nil, &iamtypes.NoSuchEntityException{Message: aws.String("no profile")}
}

type fakeOrg struct{ rcpDisabled bool }

func (f *fakeOrg) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{Id: aws.String("o-exampleorg1"), MasterAccountId: aws.String("222222222222")}}, nil
}

func (f *fakeOrg) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: aws.String("r-ab12")}}}, nil
}

func (f *fakeOrg) ListOrganizationalUnitsForParent(_ context.Context, in *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if aws.ToString(in.ParentId) == "r-ab12" {
		return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []orgtypes.OrganizationalUnit{{Id: aws.String("ou-ab12-work")}}}, nil
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
}

func (f *fakeOrg) ListAccountsForParent(_ context.Context, in *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	switch aws.ToString(in.ParentId) {
	case "r-ab12":
		return &organizations.ListAccountsForParentOutput{Accounts: []orgtypes.Account{{Id: aws.String("222222222222")}}}, nil
	case "ou-ab12-work":
		return &organizations.ListAccountsForParentOutput{Accounts: []orgtypes.Account{{Id: aws.String(acct)}}}, nil
	}
	return &organizations.ListAccountsForParentOutput{}, nil
}

func (f *fakeOrg) ListPolicies(_ context.Context, in *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if in.Filter == orgtypes.PolicyTypeResourceControlPolicy {
		if f.rcpDisabled {
			return nil, &orgtypes.PolicyTypeNotEnabledException{Message: aws.String("RCPs are not enabled")}
		}
		return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{{Id: aws.String("p-rcp1"), Name: aws.String("RCPFullAccess")}}}, nil
	}
	return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess")}}}, nil
}

func (f *fakeOrg) DescribePolicy(_ context.Context, _ *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}}, nil
}

func (f *fakeOrg) ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	return &organizations.ListTargetsForPolicyOutput{Targets: []orgtypes.PolicyTargetSummary{{TargetId: aws.String("r-ab12")}}}, nil
}

type fakeLambda struct{}

func (fakeLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: []lambdatypes.FunctionConfiguration{{
		FunctionArn: aws.String("arn:aws:lambda:us-east-1:" + acct + ":function:job"), Role: aws.String("arn:aws:iam::" + acct + ":role/admin"),
	}}}, nil
}

type fakeEC2 struct{}

func (fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
		{InstanceId: aws.String("i-0123456789abcdef0"), IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String("arn:aws:iam::" + acct + ":instance-profile/admin")}},
		{InstanceId: aws.String("i-0000000000000000f")},
	}}}}, nil
}

type fakeSSM struct{}

func (fakeSSM) DescribeInstanceInformation(context.Context, *ssm.DescribeInstanceInformationInput, ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: []ssmtypes.InstanceInformation{{InstanceId: aws.String("i-0123456789abcdef0")}}}, nil
}

type fakeCodeBuild struct{}

func (fakeCodeBuild) ListProjects(context.Context, *codebuild.ListProjectsInput, ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	return &codebuild.ListProjectsOutput{Projects: []string{"build"}}, nil
}

func (fakeCodeBuild) BatchGetProjects(context.Context, *codebuild.BatchGetProjectsInput, ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	return &codebuild.BatchGetProjectsOutput{Projects: []cbtypes.Project{{
		Arn: aws.String("arn:aws:codebuild:us-east-1:" + acct + ":project/build"), ServiceRole: aws.String("arn:aws:iam::" + acct + ":role/admin"),
	}}}, nil
}
