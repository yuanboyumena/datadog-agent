// Code generated by go generate; DO NOT EDIT.
// +build linux_bpf

package runtime

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf"
)

var Tracer = ebpf.NewRuntimeAsset("tracer.c", "56b8de84ff30aea8cf0a5d49c430f57274f9c7bccad8054dda5e6ebccb242b62")
