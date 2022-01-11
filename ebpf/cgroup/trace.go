package main

import (
	"log"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"strconv"

	"github.com/cilium/ebpf"
)

const (
	dataflowPinPath    = "/sys/fs/bpf/dataflow_map"
)

type entry struct {
	Saddr	uint32
	Daddr	uint32
	Proto	uint8
	Bitmap	uint8
}

func main() {
	// restore data flow map from pinned file on bpffs
	fl, err := ebpf.LoadPinnedMap(dataflowPinPath, nil)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Tracking ... press Ctrl + c to quit")
	// check the map at regular intervals
	tkr := time.NewTicker(time.Second)

	// capture sigint and sigterm
	chInt := make(chan os.Signal, 1)
	signal.Notify(chInt, os.Interrupt, syscall.SIGTERM)

	// protocol number to name mapping 
	protocols := map[uint8]string{1: "ICMP", 6: "TCP", 17: "UDP"}

	var ent entry
	var saddr, daddr, protocolName, entlog string
	var isIngress, isBanned bool

	loop: for {
		select {
			case <- tkr.C:
				// retrieve all the entries from the map
				for fl.LookupAndDelete(nil, &ent) == nil {
					saddr, daddr = uint32ToIPv4(ent.Saddr), uint32ToIPv4(ent.Daddr)
					isIngress, isBanned = ((ent.Bitmap & 2) >> 1) == 1, (ent.Bitmap & 1) == 1
					if val, ok := protocols[ent.Proto]; ok {
						protocolName = val
					}else{
						protocolName = strconv.Itoa(int(ent.Proto))
					}

					if isIngress {
						entlog = fmt.Sprintf("%s IN %s > %s", protocolName, saddr, daddr)
					}else{
						entlog = fmt.Sprintf("%s OUT %s > %s", protocolName, saddr, daddr)
					}

					if isBanned {
						entlog += " (BANNED)"
					}

					fmt.Println(entlog)
				}
			case <- chInt:
				break loop
		}
	}

	log.Println("Tracking stopped.")
}
