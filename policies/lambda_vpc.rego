package main

import rego.v1

# METADATA
# title: Intake Lambda runs in private VPC subnets
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(e)(1)
#   severity: high
#   remediation: Add vpc_config to aws_lambda_function.intake with private subnet IDs and a security group.
deny contains msg if {
	missing_resource("aws_lambda_function.intake")
	msg := "HIPAA 164.312(e)(1): GAP-05 intake Lambda must exist and be network governed."
}

deny contains msg if {
	r := resource("aws_lambda_function.intake")
	not valid_lambda_vpc(r)
	msg := "HIPAA 164.312(e)(1): GAP-05 intake Lambda must run inside the starter VPC private subnets."
}

valid_lambda_vpc(r) if {
	some cfg in r.values.vpc_config
	count(cfg.subnet_ids) >= 2
	count(cfg.security_group_ids) >= 1
	cfg.vpc_id != ""
}
