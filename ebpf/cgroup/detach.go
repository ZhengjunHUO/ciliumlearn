package main

import (
	"log"
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
)

const (
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

	dataflowPinPath := bpfPath + cgroupId + "_dataflow_map"
	egressLinkPinPath := bpfPath + cgroupId + "_cgroup_egs_link"
	ingressLinkPinPath := bpfPath + cgroupId + "_cgroup_igs_link"

	// restore link from pinned file on bpffs
	l, err := link.LoadPinnedCgroup(egressLinkPinPath, nil)
	if err != nil {
		log.Fatalln(err)
	}

	// remove the file on bpffs
	l.Unpin()
	l.Close()

	l, err = link.LoadPinnedCgroup(ingressLinkPinPath, nil)
	if err != nil {
		log.Fatalln(err)
	}

	// remove the file on bpffs
	l.Unpin()
	l.Close()

	os.Remove(dataflowPinPath)

	log.Println("Link unpinned")
}
