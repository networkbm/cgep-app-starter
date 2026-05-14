package main

import rego.v1

# METADATA
# title: Lambda IAM policy avoids wildcard data-store permissions
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(a)(1)
#   severity: high
#   remediation: Replace dynamodb:* and s3:* with only the required table, object, KMS, SQS, and X-Ray actions.
deny contains msg if {
	missing_resource("aws_iam_role_policy.lambda_inline")
	msg := "HIPAA 164.312(a)(1): GAP-07 Lambda inline IAM policy must exist and be least-privilege."
}

deny contains msg if {
	r := resource("aws_iam_role_policy.lambda_inline")
	not valid_lambda_iam(r)
	msg := "HIPAA 164.312(a)(1): GAP-07 Lambda IAM policy must not include wildcard service actions such as dynamodb:* or s3:*."
}

valid_lambda_iam(r) if {
	policy := json.unmarshal(r.values.policy)
	not has_overbroad_statement(policy)
}

has_overbroad_statement(policy) if {
	some statement in policy.Statement
	some action in lower_actions(statement)
	action_is_overbroad(action)
}
