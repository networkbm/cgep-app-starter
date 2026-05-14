package main

import rego.v1

test_s3_tls_policy_pass if {
	valid_tls_deny_policy({"values": {"policy": "{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"}})
}

test_s3_tls_policy_fail if {
	not valid_tls_deny_policy({"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\"}]}"}})
}
