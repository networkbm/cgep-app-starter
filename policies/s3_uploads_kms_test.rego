package main

import rego.v1

test_s3_uploads_kms_pass if {
	valid_uploads_kms({
		"values": {"rule": [{
			"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "aws:kms",
				"kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/example",
			}],
		}]},
	})
}

test_s3_uploads_kms_fail if {
	not valid_uploads_kms({
		"values": {"rule": [{
			"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "AES256",
				"kms_master_key_id": "",
			}],
		}]},
	})
}
