package pkg

import (
	"os"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ZhengjunHUO/ciliumlearn/ebpf/ctnctl/tools"
)

// Clean up the resources related to the container
func RemovePinnedResource(name string) error {
	// Get container's full ID
	cgroupId := GetContainerID(name)
	if len(cgroupId) == 0 {
		return errors.New("Invalid container name or id!\n")
	}

	// check if dir still exist
	pinPath := bpfPath + cgroupId
	if _, err := os.Stat(pinPath); err != nil {
		// dir doesn't exist, return directly
		return nil
	}

	// unpin all links related to container
	for i := range allLinks {
		l, err := link.LoadPinnedCgroup(pinPath + allLinks[i], nil)
		if err != nil {
			return err
		}

		l.Unpin()
		l.Close()
	}

	// unpin all maps related to container
	for i := range allMaps {
		m, err := ebpf.LoadPinnedMap(pinPath + allMaps[i], nil)
		if err != nil {
			return err
		}

		m.Unpin()
		m.Close()
	}

	// remove container's folder under /sys/fs/bpf
	os.Remove(bpfPath + cgroupId)
	return nil
}

// Delete an ip from the ingress/egress firewall (map)
func DelIP(ip, name string, isIngress bool) error {
	var fw *ebpf.Map
	err := LoadPinnedMap(&fw, name, isIngress)
	if err != nil {
		return err
	}

	ipToAdd := tools.Ipv4ToUint32(ip)
	if err := fw.Delete(&ipToAdd); err != nil {
		return err
	}

	return nil
}
