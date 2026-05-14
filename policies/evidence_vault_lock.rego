package main

import rego.v1

# METADATA
# title: Evidence vault has Object Lock retention
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(c)(1)
#     - 164.312(b)
#   severity: high
#   remediation: Add aws_s3_bucket_object_lock_configuration.evidence with default retention in GOVERNANCE or COMPLIANCE mode.
deny contains msg if {
	missing_resource("aws_s3_bucket_object_lock_configuration.evidence")
	msg := "HIPAA 164.312(c)(1): evidence vault must use S3 Object Lock retention for audit evidence integrity."
}

deny contains msg if {
	r := resource("aws_s3_bucket_object_lock_configuration.evidence")
	not valid_evidence_object_lock(r)
	msg := "HIPAA 164.312(c)(1): evidence vault Object Lock must be enabled with GOVERNANCE or COMPLIANCE retention."
}

valid_evidence_object_lock(r) if {
	r.values.object_lock_enabled == "Enabled"
	some rule in r.values.rule
	some retention in rule.default_retention
	retention.days >= 30
	retention.mode in {"GOVERNANCE", "COMPLIANCE"}
}
