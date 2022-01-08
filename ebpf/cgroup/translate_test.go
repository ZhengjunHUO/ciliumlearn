package main

import (
	"testing"
)

var (
	ns = [4]uint32{50336172, 33558956, 67373064, 23505088}
	ips = [4]string{"172.17.0.3", "172.17.0.2", "8.8.4.4", "192.168.102.1"}
)

func TestUint32ToIPv4(t *testing.T) {
	for i := range ns {
		if ip := uint32ToIPv4(ns[i]); ip != ips[i] {
			t.Errorf("uint32ToIPv4(%v) return %v but expect %v\n", ns[i], ip, ips[i])
		}
	}
}

func TestIpv4ToUint32(t *testing.T) {
	for i := range ips {
		if n := ipv4ToUint32(ips[i]); n != ns[i] {
			t.Errorf("ipv4ToUint32(%v) return %v but expect %v\n", ips[i], n, ns[i])
		}
	}
}

