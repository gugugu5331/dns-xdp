module xdp-dns

go 1.24.0

toolchain go1.24.10

require (
	github.com/cilium/ebpf v0.20.0
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.38.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/vishvananda/netns v0.0.5 // indirect
