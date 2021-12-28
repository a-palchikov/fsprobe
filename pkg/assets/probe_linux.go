package assets

import (
	_ "embed"
)

//go:embed ebpf/bytecode/probe.o
var Probe []byte
