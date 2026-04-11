module github.com/fimbulwinter/veronica

go 1.26.1

require (
	github.com/Agent-Field/agentfield/sdk/go v0.1.25
	github.com/cilium/ebpf v0.21.0
	github.com/goccy/go-json v0.10.6
)

require (
	golang.org/x/sys v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/Agent-Field/agentfield/sdk/go v0.1.25 => github.com/Agent-Field/agentfield/sdk/go v0.0.0-20260411010315-aaa3f004f7f1
