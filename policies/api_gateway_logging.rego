package main

import rego.v1

# METADATA
# title: API Gateway stage emits access logs and throttles requests
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - 164.312(b)
#   severity: medium
#   remediation: Add access_log_settings and default_route_settings throttling to aws_apigatewayv2_stage.default.
deny contains msg if {
	missing_resource("aws_apigatewayv2_stage.default")
	msg := "HIPAA 164.312(b): GAP-08 API Gateway stage must exist and emit audit records."
}

deny contains msg if {
	r := resource("aws_apigatewayv2_stage.default")
	not valid_api_gateway_logging(r)
	msg := "HIPAA 164.312(b): GAP-08 API Gateway must have access logs plus burst and rate throttling."
}

valid_api_gateway_logging(r) if {
	some logs in r.values.access_log_settings
	logs.destination_arn != ""
	contains(logs.format, "$context.requestId")
	some settings in r.values.default_route_settings
	settings.throttling_burst_limit > 0
	settings.throttling_rate_limit > 0
}
