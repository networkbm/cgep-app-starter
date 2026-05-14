package main

import rego.v1

# METADATA
# title: S3 uploads bucket uses customer-managed KMS encryption
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(a)(2)(iv)
#   severity: high
#   remediation: Add aws_s3_bucket_server_side_encryption_configuration.uploads with sse_algorithm aws:kms and the Acme CMK ARN.
deny contains msg if {
	missing_resource("aws_s3_bucket_server_side_encryption_configuration.uploads")
	msg := "HIPAA 164.312(a)(2)(iv): GAP-01 uploads bucket must use SSE-KMS with a customer-managed KMS key."
}

deny contains msg if {
	r := resource("aws_s3_bucket_server_side_encryption_configuration.uploads")
	not valid_uploads_kms(r)
	msg := "HIPAA 164.312(a)(2)(iv): GAP-01 uploads bucket encryption must be aws:kms with a customer-managed key."
}

valid_uploads_kms(r) if {
	some rule in r.values.rule
	some enc in rule.apply_server_side_encryption_by_default
	enc.sse_algorithm == "aws:kms"
	enc.kms_master_key_id != ""
}
