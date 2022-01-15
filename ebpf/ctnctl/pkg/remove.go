package pkg

import (
	"os"
	"errors"

	"github.com/cilium/ebpf/link"
)

func RemovePinnedResource(name string) error {
	// Get container's full ID
	cgroupId := GetContainerID(name)
	if len(cgroupId) == 0 {
		return errors.New("Invalid container name or id!\n")
	}

	pinPath := bpfPath + cgroupId
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
