package main

import rego.v1

test_dynamodb_cmk_pass if {
	valid_dynamodb_cmk({"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn"}]}})
}

test_dynamodb_cmk_fail if {
	not valid_dynamodb_cmk({"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": ""}]}})
}
