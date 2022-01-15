package pkg

import (
	"os"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ZhengjunHUO/ciliumlearn/ebpf/ctnctl/tools"
)

func CreateLinkIfNotExit(name string) error {
	// Get container's full ID
	cgroupId := GetContainerID(name)
	if len(cgroupId) == 0 {
		return errors.New("Invalid container name or id!\n")
	}
	// Get related cgroup path
	cgroupPath := "/sys/fs/cgroup/system.slice/docker-"+cgroupId+".scope"

	dataflowPinPath := bpfPath + cgroupId + "_dataflow_map"
	egressMapPinPath := bpfPath + cgroupId + "_egs_map"
	ingressMapPinPath := bpfPath + cgroupId + "_igs_map"

	egressLinkPinPath := bpfPath + cgroupId + "_cgroup_egs_link"
	ingressLinkPinPath := bpfPath + cgroupId + "_cgroup_igs_link"

	if _, err := os.Stat(dataflowPinPath); err == nil {
		// file exist, return directly
		return nil
	}

	/* remove ebpf lock memory limit */
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Pin links and maps
	/* load precompiled bpf program */
	collection, err := ebpf.LoadCollection(bpfProgName)
	if err != nil {
		return err
	}
	ingressFunc := collection.Programs[ingressFuncName]
	egressFunc := collection.Programs[egressFuncName]

	/* load map (temporary hardcode an entry to blacklist) */
	egressMap := collection.Maps[egressMapName]
	ingressMap := collection.Maps[ingressMapName]
	flowMap := collection.Maps[flowMapName]

	egressMap.Pin(egressMapPinPath)
	ingressMap.Pin(ingressMapPinPath)
	flowMap.Pin(dataflowPinPath)

	/* attach bpf program to specific cgroup */
	lnk_egs, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: egressFunc,
	})
	if err != nil {
		return err
	}

	lnk_igs, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: ingressFunc,
	})
	if err != nil {
		return err
	}

	/* pin link to the bpffs */
	lnk_egs.Pin(egressLinkPinPath)
	lnk_egs.Close()

	lnk_igs.Pin(ingressLinkPinPath)
	lnk_igs.Close()

	return nil
}

func AddIP(ip, name string, isIngress bool) error {
	//var fw *ebpf.Map
	//fw, err := LoadPinnedMap(fw, name, isIngress)
	bTrue := true

	fw, err := LoadPinnedMap(name, isIngress)
	if err != nil {
		return err
	}

	ipToAdd := tools.Ipv4ToUint32(ip)
	if err := fw.Put(&ipToAdd, &bTrue); err != nil {
		return err
	}

	return nil
}