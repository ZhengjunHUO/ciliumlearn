package main

import (
	"encoding/binary"
	"net"
	"os/exec"
	"fmt"
)

// translate ipv4 address in skb (uint32) to string (eg. 1.2.3.4)
func uint32ToIPv4(n uint32) string {
	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], n)

	return net.IPv4(buffer[0], buffer[1], buffer[2], buffer[3]).String()
}

// parse a ipv4 address in format string to a uint32 
func ipv4ToUint32(s string) uint32 {
	return binary.LittleEndian.Uint32(net.ParseIP(s).To4())
}

// Return container's fullid and cgroup path
//   eg. /sys/fs/cgroup/system.slice/docker-5b81537a967793cf5c8b562bd5b9cb6b55045ed339ed328390f70d466aa84134.scope
func GetContainerID(name string) string {
	cid, err := exec.Command("docker", "inspect", "--format", "\"{{.Id}}\"", name).Output()
	if err != nil {
		fmt.Printf("Error get container [%s]'s id: %s\n", name, err)
		return ""
	}

	return string(cid[1:len(cid)-2])
}
