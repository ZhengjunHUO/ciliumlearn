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

	// Get related cgroup (v2, docker use systemd driver by default) path
	cgroupPath := "/sys/fs/cgroup/system.slice/docker-"+cgroupId+".scope"
	/*
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		// fallback to cgroup v1, docker use cgroupfs driver by default
		cgroupPath = "/sys/fs/cgroup/net_cls,net_prio/docker/"+cgroupId
	}
	*/

	// Check if dir exist
	pinPath := bpfPath + cgroupId
	if _, err := os.Stat(pinPath); err == nil {
		// file exist, return directly
		return nil
	}

	// remove ebpf lock memory limit
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
	egressL4MapPinPath := pinPath + "/egs_l4_map"
	ingressL4MapPinPath := pinPath + "/igs_l4_map"
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

	// get functions from bpf program
	ingressFunc := collection.Programs[ingressFuncName]
	egressFunc := collection.Programs[egressFuncName]

	// get maps from bpf program
	egressMap := collection.Maps[egressMapName]
	ingressMap := collection.Maps[ingressMapName]
	egressL4Map := collection.Maps[egressL4MapName]
	ingressL4Map := collection.Maps[ingressL4MapName]
	flowMap := collection.Maps[flowMapName]

	// pin maps to bpffs
	egressMap.Pin(egressMapPinPath)
	ingressMap.Pin(ingressMapPinPath)
	egressL4Map.Pin(egressL4MapPinPath)
	ingressL4Map.Pin(ingressL4MapPinPath)
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

	// load pinned map from bpffs
	err := LoadPinnedMap(&fw, name, isIngress, true)
	if err != nil {
		return err
	}

	// add new rule to pinned map
	ipToAdd := tools.Ipv4ToUint32(ip)
	if err := fw.Put(&ipToAdd, &bTrue); err != nil {
		return err
	}

	return nil
}

// Add an ip:port entry to the ingress/egress l4 firewall (map)
func AddIPPort(ip, name string, port uint16, isIngress bool) error {
	var fw *ebpf.Map
	bTrue := true

	// load pinned map from bpffs
	err := LoadPinnedMap(&fw, name, isIngress, false)
	if err != nil {
		return err
	}

	// add new rule to pinned map
	skt := socket{tools.Ipv4ToUint32(ip), tools.Uint16ToPort(port), 0}
	if err := fw.Put(&skt, &bTrue); err != nil {
		return err
	}

	return nil
}
