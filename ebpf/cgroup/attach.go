package main

import (
	"fmt"
	"log"
	"net"
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	//cgroupPath      = "/sys/fs/cgroup/system.slice/docker-746823468eb932764abff0bc416aa39d96037d201976b293ccb66c10c4702567.scope"
	cgroupPath	= "/sys/fs/cgroup/system.slice/docker-5b81537a967793cf5c8b562bd5b9cb6b55045ed339ed328390f70d466aa84134.scope"

	bpfProgName	= "bpf.o"
	egressFuncName  = "egress_filter"
	ingressFuncName = "ingress_filter"
	egressMapName   = "egress_blacklist"
	ingressMapName  = "ingress_blacklist"

	egressLinkPinPath     = "/sys/fs/bpf/cgroup_egs_link"
	ingressLinkPinPath    = "/sys/fs/bpf/cgroup_igs_link"
)

func main() {
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

	ip_egs := binary.LittleEndian.Uint32(net.ParseIP("8.8.4.4").To4())
	bTrue := true
	if err = egressMap.Put(&ip_egs, &bTrue); err != nil {
		log.Fatalln(err)
	}

	ip_igs := binary.LittleEndian.Uint32(net.ParseIP("172.17.0.2").To4())
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

	/* pin link to the bpffs */
	lnk_egs.Pin(egressLinkPinPath)
	lnk_egs.Close()

	lnk_igs.Pin(ingressLinkPinPath)
	lnk_igs.Close()

	fmt.Println("eBPF program attached.")
}
