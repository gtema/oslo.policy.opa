package test

allow if {
  input.target.foo == "bar"
  input.credentials.project_id == "pid"
}

filtered := input.target
