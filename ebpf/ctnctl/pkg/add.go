package pkg

import (
	"os"
	"errors"
	"bytes"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ZhengjunHUO/ciliumlearn/ebpf/ctnctl/tools"
)

// Load ebpf bytecode to kernel (if not loaded yet), pin links and maps to bpffs
func CreateLinkIfNotExit(name string) error {
	// Get container's full ID
	cgroupId := GetContainerID(name)
	if len(cgroupId) == 0 {
		return errors.New("Invalid container name or id!\n")
	}
	// Get related cgroup path
	cgroupPath := "/sys/fs/cgroup/system.slice/docker-"+cgroupId+".scope"

	// Check if dir exist
	pinPath := bpfPath + cgroupId
	if _, err := os.Stat(pinPath); err == nil {
		// file exist, return directly
		return nil
	}

	/* remove ebpf lock memory limit */
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Create dir associated to container
	if err := os.Mkdir(pinPath, os.ModePerm); err != nil {
		return err
	}

	dataflowPinPath := pinPath + "/dataflow_map"
	egressMapPinPath := pinPath + "/egs_map"
	ingressMapPinPath := pinPath + "/igs_map"
	egressLinkPinPath := pinPath + "/cgroup_egs_link"
	ingressLinkPinPath := pinPath + "/cgroup_igs_link"

	// load precompiled bpf program
	//collection, err := ebpf.LoadCollection(bpfProgName)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgBytes))
	if err != nil {
		return err
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	ingressFunc := collection.Programs[ingressFuncName]
	egressFunc := collection.Programs[egressFuncName]

	// load maps
	egressMap := collection.Maps[egressMapName]
	ingressMap := collection.Maps[ingressMapName]
	flowMap := collection.Maps[flowMapName]

	// Pin maps
	egressMap.Pin(egressMapPinPath)
	ingressMap.Pin(ingressMapPinPath)
	flowMap.Pin(dataflowPinPath)

	// attach bpf program to specific cgroup 
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

	// pin links
	lnk_egs.Pin(egressLinkPinPath)
	lnk_egs.Close()

	lnk_igs.Pin(ingressLinkPinPath)
	lnk_igs.Close()

	return nil
}

// Add an ip to the ingress/egress firewall (map)
func AddIP(ip, name string, isIngress bool) error {
	var fw *ebpf.Map
	bTrue := true

	err := LoadPinnedMap(&fw, name, isIngress)
	if err != nil {
		return err
	}

	ipToAdd := tools.Ipv4ToUint32(ip)
	if err := fw.Put(&ipToAdd, &bTrue); err != nil {
		return err
	}

	return nil
}
