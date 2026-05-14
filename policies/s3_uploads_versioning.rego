package main

import rego.v1

# METADATA
# title: S3 uploads bucket versioning is enabled
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.308(a)(7)
#   severity: medium
#   remediation: Add aws_s3_bucket_versioning.uploads with status Enabled.
deny contains msg if {
	missing_resource("aws_s3_bucket_versioning.uploads")
	msg := "HIPAA 164.308(a)(7): GAP-04 uploads bucket must have versioning enabled for recovery."
}

deny contains msg if {
	r := resource("aws_s3_bucket_versioning.uploads")
	not valid_uploads_versioning(r)
	msg := "HIPAA 164.308(a)(7): GAP-04 uploads bucket versioning status must be Enabled."
}

valid_uploads_versioning(r) if {
	some cfg in r.values.versioning_configuration
	cfg.status == "Enabled"
}
