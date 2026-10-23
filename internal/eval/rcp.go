package eval

import "strings"

// rcpServices lists the service prefixes whose actions RCPs apply to,
// verified on 2026-10-23 in
// https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
// Notably sts is covered and iam is not (edge cases E10, E11).
var rcpServices = map[string]bool{
	"appstream": true, "dsql": true, "clouddirectory": true, "cloudfront": true,
	"cloudsearch": true, "logs": true, "networkmonitor": true, "cognito-identity": true,
	"cognito-idp": true, "comprehend": true, "comprehendmedical": true, "firehose": true,
	"dynamodb": true, "dax": true, "autoscaling": true, "ecr": true, "ecr-public": true,
	"gamelift": true, "inspector-scan": true, "kendra": true, "kinesisvideo": true,
	"memorydb": true, "aoss": true, "personalize": true, "polly": true, "s3": true,
	"swf": true, "sqs": true, "textract": true, "timestream-influxdb": true,
	"transcribe": true, "translate": true, "workspaces": true, "appconfig": true,
	"autoscaling-plans": true, "budgets": true, "servicediscovery": true,
	"cloudtrail-data": true, "codeartifact": true, "codebuild": true, "codecommit": true,
	"codepipeline": true, "compute-optimizer": true, "cost-optimization-hub": true,
	"events": true, "fms": true, "fis": true, "health": true, "rolesanywhere": true,
	"kms": true, "opensearch": true, "pricing": true, "pca-connector-ad": true,
	"resource-groups": true, "secretsmanager": true, "sts": true, "signin": true,
	"support": true, "transfer": true, "notifications": true, "wafv2": true, "xray": true,
}

// RCPApplies reports whether RCPs can restrict the action.
func RCPApplies(action string) bool {
	prefix, _, _ := strings.Cut(strings.ToLower(action), ":")
	return rcpServices[prefix]
}
