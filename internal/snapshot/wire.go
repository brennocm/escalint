package snapshot

import "encoding/json/jsontext"

// Wire types mirror the JSON returned by the AWS CLI / SDK for
// GetAccountAuthorizationDetails and the escalint envelope. They are decoded
// with encoding/json/v2, which matches field names case-sensitively (v1
// would also accept "arn" for "Arn", and keep whichever comes last).
// Unknown fields are ignored so new AWS fields do not break loading. Policy documents stay
// raw because they arrive as objects (CLI), JSON strings or URL-encoded
// strings (SDK).

type wireAuthorizationDetails struct {
	UserDetailList  []wireUser          `json:"UserDetailList"`
	GroupDetailList []wireGroup         `json:"GroupDetailList"`
	RoleDetailList  []wireRole          `json:"RoleDetailList"`
	Policies        []wireManagedPolicy `json:"Policies"`
}

type wirePolicyDetail struct {
	PolicyName     string         `json:"PolicyName"`
	PolicyDocument jsontext.Value `json:"PolicyDocument"`
}

type wireAttachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type wireBoundary struct {
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
}

type wireTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type wireUser struct {
	Path                    string               `json:"Path"`
	UserName                string               `json:"UserName"`
	UserID                  string               `json:"UserId"`
	Arn                     string               `json:"Arn"`
	UserPolicyList          []wirePolicyDetail   `json:"UserPolicyList"`
	GroupList               []string             `json:"GroupList"`
	AttachedManagedPolicies []wireAttachedPolicy `json:"AttachedManagedPolicies"`
	PermissionsBoundary     *wireBoundary        `json:"PermissionsBoundary"`
	Tags                    []wireTag            `json:"Tags"`
}

type wireGroup struct {
	Path                    string               `json:"Path"`
	GroupName               string               `json:"GroupName"`
	GroupID                 string               `json:"GroupId"`
	Arn                     string               `json:"Arn"`
	GroupPolicyList         []wirePolicyDetail   `json:"GroupPolicyList"`
	AttachedManagedPolicies []wireAttachedPolicy `json:"AttachedManagedPolicies"`
}

type wireInstanceProfile struct {
	InstanceProfileName string `json:"InstanceProfileName"`
	Arn                 string `json:"Arn"`
}

type wireRoleLastUsed struct {
	LastUsedDate string `json:"LastUsedDate"`
	Region       string `json:"Region"`
}

type wireRole struct {
	Path                     string                `json:"Path"`
	RoleName                 string                `json:"RoleName"`
	RoleID                   string                `json:"RoleId"`
	Arn                      string                `json:"Arn"`
	AssumeRolePolicyDocument jsontext.Value        `json:"AssumeRolePolicyDocument"`
	InstanceProfileList      []wireInstanceProfile `json:"InstanceProfileList"`
	RolePolicyList           []wirePolicyDetail    `json:"RolePolicyList"`
	AttachedManagedPolicies  []wireAttachedPolicy  `json:"AttachedManagedPolicies"`
	PermissionsBoundary      *wireBoundary         `json:"PermissionsBoundary"`
	Tags                     []wireTag             `json:"Tags"`
	RoleLastUsed             *wireRoleLastUsed     `json:"RoleLastUsed"`
}

type wirePolicyVersion struct {
	Document         jsontext.Value `json:"Document"`
	VersionID        string         `json:"VersionId"`
	IsDefaultVersion bool           `json:"IsDefaultVersion"`
}

type wireManagedPolicy struct {
	PolicyName        string              `json:"PolicyName"`
	PolicyID          string              `json:"PolicyId"`
	Arn               string              `json:"Arn"`
	Path              string              `json:"Path"`
	DefaultVersionID  string              `json:"DefaultVersionId"`
	PolicyVersionList []wirePolicyVersion `json:"PolicyVersionList"`
}

type wireEnvelope struct {
	Version     string `json:"escalint_snapshot"`
	CollectedAt string `json:"collected_at"`
	Collector   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"collector"`
	Partition    string            `json:"partition"`
	Accounts     []wireAccount     `json:"accounts"`
	Organization *wireOrganization `json:"organization"`
}

type wireAccount struct {
	AccountID            string                   `json:"account_id"`
	AuthorizationDetails wireAuthorizationDetails `json:"authorization_details"`
	IdentityProviders    *struct {
		OIDC []struct {
			Arn       string   `json:"arn"`
			URL       string   `json:"url"`
			ClientIDs []string `json:"client_ids"`
		} `json:"oidc"`
		SAML []struct {
			Arn string `json:"arn"`
		} `json:"saml"`
	} `json:"identity_providers"`
	Extras *struct {
		AccessKeys map[string][]struct {
			Status string `json:"status"`
		} `json:"access_keys"`
		LoginProfiles map[string]bool `json:"login_profiles"`
	} `json:"extras"`
	Resources *struct {
		Lambda []struct {
			Arn  string `json:"arn"`
			Role string `json:"role"`
		} `json:"lambda"`
		EC2 []struct {
			Arn             string `json:"arn"`
			InstanceProfile string `json:"instance_profile"`
			SSMManaged      bool   `json:"ssm_managed"`
		} `json:"ec2"`
		CodeBuild []struct {
			Arn         string `json:"arn"`
			ServiceRole string `json:"service_role"`
		} `json:"codebuild"`
	} `json:"resources"`
}

type wireOrganization struct {
	ID                  string `json:"id"`
	ManagementAccountID string `json:"management_account_id"`
	Tree                []struct {
		ID     string  `json:"id"`
		Type   string  `json:"type"`
		Parent *string `json:"parent"`
	} `json:"tree"`
	Policies []struct {
		ID       string         `json:"id"`
		Type     string         `json:"type"`
		Name     string         `json:"name"`
		Document jsontext.Value `json:"document"`
		Targets  []string       `json:"targets"`
	} `json:"policies"`
}
