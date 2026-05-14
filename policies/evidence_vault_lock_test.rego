package main

import rego.v1

test_evidence_vault_lock_pass if {
	valid_evidence_object_lock({"values": {"object_lock_enabled": "Enabled", "rule": [{"default_retention": [{"mode": "GOVERNANCE", "days": 30}]}]}})
}

test_evidence_vault_lock_fail if {
	not valid_evidence_object_lock({"values": {"object_lock_enabled": "Disabled", "rule": [{"default_retention": [{"mode": "GOVERNANCE", "days": 30}]}]}})
}
