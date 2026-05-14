package main

import rego.v1

# METADATA
# title: S3 uploads bucket denies non-TLS requests
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(e)(1)
#   severity: high
#   remediation: Add aws_s3_bucket_policy.uploads with a Deny on aws:SecureTransport false for bucket and object ARNs.
deny contains msg if {
	missing_resource("aws_s3_bucket_policy.uploads")
	msg := "HIPAA 164.312(e)(1): GAP-03 uploads bucket must deny non-TLS requests."
}

deny contains msg if {
	r := resource("aws_s3_bucket_policy.uploads")
	not valid_tls_deny_policy(r)
	msg := "HIPAA 164.312(e)(1): GAP-03 uploads bucket policy must deny aws:SecureTransport=false."
}

valid_tls_deny_policy(r) if {
	policy := json.unmarshal(r.values.policy)
	some statement in policy.Statement
	statement.Effect == "Deny"
	some action in lower_actions(statement)
	action == "s3:*"
	statement.Condition.Bool["aws:SecureTransport"] == "false"
}
