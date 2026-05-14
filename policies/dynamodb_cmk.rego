package main

import rego.v1

# METADATA
# title: DynamoDB submissions table uses customer-managed KMS encryption
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(a)(2)(iv)
#   severity: high
#   remediation: Add server_side_encryption to aws_dynamodb_table.intake with enabled true and kms_key_arn set to the Acme CMK.
deny contains msg if {
	missing_resource("aws_dynamodb_table.intake")
	msg := "HIPAA 164.312(a)(2)(iv): GAP-02 DynamoDB submissions table must exist and be governed."
}

deny contains msg if {
	r := resource("aws_dynamodb_table.intake")
	not valid_dynamodb_cmk(r)
	msg := "HIPAA 164.312(a)(2)(iv): GAP-02 DynamoDB submissions table must use a customer-managed KMS key."
}

valid_dynamodb_cmk(r) if {
	some enc in r.values.server_side_encryption
	enc.enabled == true
	enc.kms_key_arn != ""
}
