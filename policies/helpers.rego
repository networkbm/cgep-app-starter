package main

import rego.v1

resource(address) := r if {
	some r in input.planned_values.root_module.resources
	r.address == address
}

missing_resource(address) if {
	not resource(address)
}

as_array(value) := value if is_array(value)

as_array(value) := [value] if {
	not is_array(value)
}

lower_actions(statement) := actions if {
	actions := [lower(raw) | some raw in as_array(statement.Action)]
}

action_is_overbroad(action) if {
	action == "*"
}

action_is_overbroad(action) if {
	endswith(action, ":*")
}
