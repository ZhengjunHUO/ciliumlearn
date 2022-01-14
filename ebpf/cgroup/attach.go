package main

import (
	"log"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	bpfProgName	= "bpf.o"
	egressFuncName  = "egress_filter"
	ingressFuncName = "ingress_filter"

	egressMapName   = "egress_blacklist"
	ingressMapName  = "ingress_blacklist"
	flowMapName	= "data_flow"

	bpfPath		= "/sys/fs/bpf/"
)

func main() {
	// Wait a container name as argument
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <containerName|containerId>\n", os.Args[0])
		os.Exit(1)
	}

	// Get container's full ID
	cgroupId := GetContainerID(os.Args[1])
	if len(cgroupId) == 0 {
		os.Exit(1)
	}

	// Get related cgroup path
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", cgroupId)

	/* remove ebpf lock memory limit */
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln(err)
	}

	/* load precompiled bpf program */
	collection, err := ebpf.LoadCollection(bpfProgName)
	if err != nil {
		log.Fatalln(err)
	}
	ingressFunc := collection.Programs[ingressFuncName]
	egressFunc := collection.Programs[egressFuncName]

	/* load map (temporary hardcode an entry to blacklist) */
	egressMap := collection.Maps[egressMapName]
	ingressMap := collection.Maps[ingressMapName]
	flowMap := collection.Maps[flowMapName]

	dataflowPinPath := bpfPath + cgroupId + "_dataflow_map"
	flowMap.Pin(dataflowPinPath)

	ip_egs := ipv4ToUint32("8.8.4.4")
	bTrue := true
	if err = egressMap.Put(&ip_egs, &bTrue); err != nil {
		log.Fatalln(err)
	}

	ip_igs := ipv4ToUint32("172.17.0.2")
	if err = ingressMap.Put(&ip_igs, &bTrue); err != nil {
		log.Fatalln(err)
	}

	/* attach bpf program to specific cgroup */
	lnk_egs, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: egressFunc,
	})
	if err != nil {
		log.Fatalln(err)
	}

	lnk_igs, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: ingressFunc,
	})
	if err != nil {
		log.Fatalln(err)
	}

	egressLinkPinPath := bpfPath + cgroupId + "_cgroup_egs_link"
	ingressLinkPinPath := bpfPath + cgroupId + "_cgroup_igs_link"
	/* pin link to the bpffs */
	lnk_egs.Pin(egressLinkPinPath)
	lnk_egs.Close()

	lnk_igs.Pin(ingressLinkPinPath)
	lnk_igs.Close()

	log.Println("eBPF program attached.")
}
