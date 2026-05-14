package main

import rego.v1

test_lambda_iam_pass if {
	valid_lambda_iam({"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"],\"Resource\":\"*\"}]}"}})
}

test_lambda_iam_fail if {
	not valid_lambda_iam({"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:*\",\"s3:PutObject\"],\"Resource\":\"*\"}]}"}})
}
