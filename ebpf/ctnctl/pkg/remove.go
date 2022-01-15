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

	dataflowPinPath := bpfPath + cgroupId + "_dataflow_map"
	egressMapPinPath := bpfPath + cgroupId + "_egs_map"
	ingressMapPinPath := bpfPath + cgroupId + "_igs_map"
	egressLinkPinPath := bpfPath + cgroupId + "_cgroup_egs_link"
	ingressLinkPinPath := bpfPath + cgroupId + "_cgroup_igs_link"

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

	return nil
}
