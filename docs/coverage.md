# Coverage of pathfinding.cloud

Generated from the rule registry by `make gen-docs`; a test fails when this file is stale.

pathfinding.cloud (commit `ecc3d092e7e409497474c8d39eb92f61810d815f`) lists **92** AWS privilege escalation paths. escalint detects **33** of them.

## Covered

| pathfinding.cloud | Name | Rule | Status |
| --- | --- | --- | --- |
| [cloudformation-001](https://pathfinding.cloud/paths/aws/cloudformation-001) | iam:PassRole + cloudformation:CreateStack | [EL-PE-023](rules/EL-PE-023.md) | stable |
| [codebuild-001](https://pathfinding.cloud/paths/aws/codebuild-001) | iam:PassRole + codebuild:CreateProject + codebuild:StartBuild | [EL-PE-024](rules/EL-PE-024.md) | stable |
| [codebuild-002](https://pathfinding.cloud/paths/aws/codebuild-002) | codebuild:StartBuild | [EL-PE-030](rules/EL-PE-030.md) | experimental |
| [ec2-001](https://pathfinding.cloud/paths/aws/ec2-001) | iam:PassRole + ec2:RunInstances | [EL-PE-021](rules/EL-PE-021.md) | stable |
| [ecs-002](https://pathfinding.cloud/paths/aws/ecs-002) | iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:RunTask | [EL-PE-026](rules/EL-PE-026.md) | experimental |
| [ecs-004](https://pathfinding.cloud/paths/aws/ecs-004) | iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask | [EL-PE-026](rules/EL-PE-026.md) | experimental |
| [glue-003](https://pathfinding.cloud/paths/aws/glue-003) | iam:PassRole + glue:CreateJob + glue:StartJobRun | [EL-PE-025](rules/EL-PE-025.md) | stable |
| [iam-001](https://pathfinding.cloud/paths/aws/iam-001) | iam:CreatePolicyVersion | [EL-PE-001](rules/EL-PE-001.md) | stable |
| [iam-002](https://pathfinding.cloud/paths/aws/iam-002) | iam:CreateAccessKey | [EL-PE-009](rules/EL-PE-009.md) | stable |
| [iam-003](https://pathfinding.cloud/paths/aws/iam-003) | iam:CreateAccessKey + iam:DeleteAccessKey | [EL-PE-010](rules/EL-PE-010.md) | stable |
| [iam-004](https://pathfinding.cloud/paths/aws/iam-004) | iam:CreateLoginProfile | [EL-PE-011](rules/EL-PE-011.md) | stable |
| [iam-005](https://pathfinding.cloud/paths/aws/iam-005) | iam:PutRolePolicy | [EL-PE-002](rules/EL-PE-002.md) | stable |
| [iam-006](https://pathfinding.cloud/paths/aws/iam-006) | iam:UpdateLoginProfile | [EL-PE-012](rules/EL-PE-012.md) | stable |
| [iam-007](https://pathfinding.cloud/paths/aws/iam-007) | iam:PutUserPolicy | [EL-PE-003](rules/EL-PE-003.md) | stable |
| [iam-008](https://pathfinding.cloud/paths/aws/iam-008) | iam:AttachUserPolicy | [EL-PE-004](rules/EL-PE-004.md) | stable |
| [iam-009](https://pathfinding.cloud/paths/aws/iam-009) | iam:AttachRolePolicy | [EL-PE-005](rules/EL-PE-005.md) | stable |
| [iam-010](https://pathfinding.cloud/paths/aws/iam-010) | iam:AttachGroupPolicy | [EL-PE-006](rules/EL-PE-006.md) | stable |
| [iam-011](https://pathfinding.cloud/paths/aws/iam-011) | iam:PutGroupPolicy | [EL-PE-007](rules/EL-PE-007.md) | stable |
| [iam-012](https://pathfinding.cloud/paths/aws/iam-012) | iam:UpdateAssumeRolePolicy | [EL-PE-013](rules/EL-PE-013.md) | stable |
| [iam-013](https://pathfinding.cloud/paths/aws/iam-013) | iam:AddUserToGroup | [EL-PE-008](rules/EL-PE-008.md) | stable |
| [iam-014](https://pathfinding.cloud/paths/aws/iam-014) | iam:AttachRolePolicy + sts:AssumeRole | [EL-PE-015](rules/EL-PE-015.md) | stable |
| [iam-015](https://pathfinding.cloud/paths/aws/iam-015) | iam:AttachUserPolicy + iam:CreateAccessKey | [EL-PE-018](rules/EL-PE-018.md) | stable |
| [iam-016](https://pathfinding.cloud/paths/aws/iam-016) | iam:CreatePolicyVersion + sts:AssumeRole | [EL-PE-016](rules/EL-PE-016.md) | stable |
| [iam-017](https://pathfinding.cloud/paths/aws/iam-017) | iam:PutRolePolicy + sts:AssumeRole | [EL-PE-017](rules/EL-PE-017.md) | stable |
| [iam-018](https://pathfinding.cloud/paths/aws/iam-018) | iam:PutUserPolicy + iam:CreateAccessKey | [EL-PE-019](rules/EL-PE-019.md) | stable |
| [iam-019](https://pathfinding.cloud/paths/aws/iam-019) | iam:AttachRolePolicy + iam:UpdateAssumeRolePolicy | [EL-PE-020](rules/EL-PE-020.md) | stable |
| [iam-020](https://pathfinding.cloud/paths/aws/iam-020) | iam:CreatePolicyVersion + iam:UpdateAssumeRolePolicy | [EL-PE-020](rules/EL-PE-020.md) | stable |
| [iam-021](https://pathfinding.cloud/paths/aws/iam-021) | iam:PutRolePolicy + iam:UpdateAssumeRolePolicy | [EL-PE-020](rules/EL-PE-020.md) | stable |
| [lambda-001](https://pathfinding.cloud/paths/aws/lambda-001) | iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction | [EL-PE-022](rules/EL-PE-022.md) | stable |
| [lambda-004](https://pathfinding.cloud/paths/aws/lambda-004) | lambda:UpdateFunctionCode + lambda:InvokeFunction | [EL-PE-028](rules/EL-PE-028.md) | stable |
| [sagemaker-001](https://pathfinding.cloud/paths/aws/sagemaker-001) | iam:PassRole + sagemaker:CreateNotebookInstance | [EL-PE-027](rules/EL-PE-027.md) | stable |
| [ssm-002](https://pathfinding.cloud/paths/aws/ssm-002) | ssm:SendCommand | [EL-PE-029](rules/EL-PE-029.md) | experimental |
| [sts-001](https://pathfinding.cloud/paths/aws/sts-001) | sts:AssumeRole | [EL-PE-014](rules/EL-PE-014.md) | stable |

## Not covered yet

| Category | Paths |
| --- | --- |
| existing-passrole | [apprunner-002](https://pathfinding.cloud/paths/aws/apprunner-002), [batch-002](https://pathfinding.cloud/paths/aws/batch-002), [bedrock-002](https://pathfinding.cloud/paths/aws/bedrock-002), [bedrock-004](https://pathfinding.cloud/paths/aws/bedrock-004), [bedrock-007](https://pathfinding.cloud/paths/aws/bedrock-007), [cloudformation-002](https://pathfinding.cloud/paths/aws/cloudformation-002), [codebuild-003](https://pathfinding.cloud/paths/aws/codebuild-003), [codedeploy-001](https://pathfinding.cloud/paths/aws/codedeploy-001), [ec2-002](https://pathfinding.cloud/paths/aws/ec2-002), [ec2-004](https://pathfinding.cloud/paths/aws/ec2-004), [ec2-005](https://pathfinding.cloud/paths/aws/ec2-005), [ec2instanceconnect-003](https://pathfinding.cloud/paths/aws/ec2instanceconnect-003), [ecs-006](https://pathfinding.cloud/paths/aws/ecs-006), [glue-002](https://pathfinding.cloud/paths/aws/glue-002), [lambda-003](https://pathfinding.cloud/paths/aws/lambda-003), [lambda-005](https://pathfinding.cloud/paths/aws/lambda-005), [sagemaker-004](https://pathfinding.cloud/paths/aws/sagemaker-004), [sagemaker-005](https://pathfinding.cloud/paths/aws/sagemaker-005), [ssm-001](https://pathfinding.cloud/paths/aws/ssm-001), [stepfunctions-002](https://pathfinding.cloud/paths/aws/stepfunctions-002) |
| new-passrole | [apprunner-001](https://pathfinding.cloud/paths/aws/apprunner-001), [batch-001](https://pathfinding.cloud/paths/aws/batch-001), [batch-003](https://pathfinding.cloud/paths/aws/batch-003), [bedrock-001](https://pathfinding.cloud/paths/aws/bedrock-001), [bedrock-003](https://pathfinding.cloud/paths/aws/bedrock-003), [bedrock-005](https://pathfinding.cloud/paths/aws/bedrock-005), [bedrock-006](https://pathfinding.cloud/paths/aws/bedrock-006), [braket-001](https://pathfinding.cloud/paths/aws/braket-001), [cloudformation-003](https://pathfinding.cloud/paths/aws/cloudformation-003), [cloudformation-004](https://pathfinding.cloud/paths/aws/cloudformation-004), [cloudformation-005](https://pathfinding.cloud/paths/aws/cloudformation-005), [codebuild-004](https://pathfinding.cloud/paths/aws/codebuild-004), [cognitoidentity-001](https://pathfinding.cloud/paths/aws/cognitoidentity-001), [datapipeline-001](https://pathfinding.cloud/paths/aws/datapipeline-001), [ec2-003](https://pathfinding.cloud/paths/aws/ec2-003), [ecs-001](https://pathfinding.cloud/paths/aws/ecs-001), [ecs-003](https://pathfinding.cloud/paths/aws/ecs-003), [ecs-005](https://pathfinding.cloud/paths/aws/ecs-005), [ecs-007](https://pathfinding.cloud/paths/aws/ecs-007), [ecs-008](https://pathfinding.cloud/paths/aws/ecs-008), [ecs-009](https://pathfinding.cloud/paths/aws/ecs-009), [emr-001](https://pathfinding.cloud/paths/aws/emr-001), [emrserverless-001](https://pathfinding.cloud/paths/aws/emrserverless-001), [gamelift-001](https://pathfinding.cloud/paths/aws/gamelift-001), [glue-001](https://pathfinding.cloud/paths/aws/glue-001), [glue-004](https://pathfinding.cloud/paths/aws/glue-004), [glue-005](https://pathfinding.cloud/paths/aws/glue-005), [glue-006](https://pathfinding.cloud/paths/aws/glue-006), [glue-007](https://pathfinding.cloud/paths/aws/glue-007), [imagebuilder-001](https://pathfinding.cloud/paths/aws/imagebuilder-001), [kinesisanalytics-001](https://pathfinding.cloud/paths/aws/kinesisanalytics-001), [lambda-002](https://pathfinding.cloud/paths/aws/lambda-002), [lambda-006](https://pathfinding.cloud/paths/aws/lambda-006), [omics-001](https://pathfinding.cloud/paths/aws/omics-001), [sagemaker-002](https://pathfinding.cloud/paths/aws/sagemaker-002), [sagemaker-003](https://pathfinding.cloud/paths/aws/sagemaker-003), [scheduler-001](https://pathfinding.cloud/paths/aws/scheduler-001), [ssm-003](https://pathfinding.cloud/paths/aws/ssm-003), [stepfunctions-001](https://pathfinding.cloud/paths/aws/stepfunctions-001) |

Most uncovered paths pass a role to another compute service (new-passrole) or change an existing resource that runs as a role (existing-passrole). Each follows the same template as the covered ones; see CONTRIBUTING.md for how to add a rule.

## Trust and parse rules

These rules have no pathfinding.cloud counterpart.

| Rule | Title | Severity | Status |
| --- | --- | --- | --- |
| [EL-PARSE-001](rules/EL-PARSE-001.md) | Policy document could not be parsed | info | stable |
| [EL-PARSE-002](rules/EL-PARSE-002.md) | Referenced policy or group is not in the snapshot | info | stable |
| [EL-PARSE-003](rules/EL-PARSE-003.md) | Suppression without a justification | info | stable |
| [EL-TR-001](rules/EL-TR-001.md) | Role trusts any AWS principal | critical | stable |
| [EL-TR-002](rules/EL-TR-002.md) | GitHub Actions OIDC trust without a sub condition | critical | stable |
| [EL-TR-003](rules/EL-TR-003.md) | GitHub Actions OIDC trust with a broad sub pattern | high | stable |
| [EL-TR-004](rules/EL-TR-004.md) | Trust to an external account outside the allowlist | medium | stable |
| [EL-TR-005](rules/EL-TR-005.md) | Third-party trust without sts:ExternalId | high | stable |
| [EL-TR-006](rules/EL-TR-006.md) | OIDC or SAML trust without an audience or subject condition | medium | experimental |
