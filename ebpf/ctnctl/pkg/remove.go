package pkg

import (
	"os"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ZhengjunHUO/ciliumlearn/ebpf/ctnctl/tools"
)

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

	dataflowPinPath := pinPath + "/dataflow_map"
	egressMapPinPath := pinPath + "/egs_map"
	ingressMapPinPath := pinPath + "/igs_map"
	egressLinkPinPath := pinPath + "/cgroup_egs_link"
	ingressLinkPinPath := pinPath + "/cgroup_igs_link"

	// restore link from pinned file on bpffs
	l, err := link.LoadPinnedCgroup(egressLinkPinPath, nil)
	if err != nil {
		return err
	}

	// remove the file on bpffs
	l.Unpin()
	l.Close()

	l, err = link.LoadPinnedCgroup(ingressLinkPinPath, nil)
	if err != nil {
		return err
	}

	// remove the file on bpffs
	l.Unpin()
	l.Close()

	os.Remove(dataflowPinPath)
	os.Remove(egressMapPinPath)
	os.Remove(ingressMapPinPath)
	os.Remove(bpfPath + cgroupId)

	return nil
}

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
