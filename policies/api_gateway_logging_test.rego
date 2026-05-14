package main

import rego.v1

test_api_gateway_logging_pass if {
	valid_api_gateway_logging({"values": {
		"access_log_settings": [{"destination_arn": "arn", "format": "$context.requestId"}],
		"default_route_settings": [{"throttling_burst_limit": 100, "throttling_rate_limit": 50}],
	}})
}

test_api_gateway_logging_fail if {
	not valid_api_gateway_logging({"values": {
		"access_log_settings": [],
		"default_route_settings": [{"throttling_burst_limit": 0, "throttling_rate_limit": 0}],
	}})
}
