package main

import rego.v1

test_s3_uploads_versioning_pass if {
	valid_uploads_versioning({"values": {"versioning_configuration": [{"status": "Enabled"}]}})
}

test_s3_uploads_versioning_fail if {
	not valid_uploads_versioning({"values": {"versioning_configuration": [{"status": "Suspended"}]}})
}
