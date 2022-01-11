package main

import (
	"log"
	"os"

	"github.com/cilium/ebpf/link"
)

const (
	egressLinkPinPath  = "/sys/fs/bpf/cgroup_egs_link"
	ingressLinkPinPath = "/sys/fs/bpf/cgroup_igs_link"
	dataflowPinPath    = "/sys/fs/bpf/dataflow_map"
)

func main() {
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
