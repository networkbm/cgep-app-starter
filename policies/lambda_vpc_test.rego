package main

import rego.v1

test_lambda_vpc_pass if {
	valid_lambda_vpc({"values": {"vpc_config": [{"subnet_ids": ["subnet-a", "subnet-b"], "security_group_ids": ["sg-a"], "vpc_id": "vpc-a"}]}})
}

test_lambda_vpc_fail if {
	not valid_lambda_vpc({"values": {"vpc_config": []}})
}
