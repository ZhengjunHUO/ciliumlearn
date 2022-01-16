package pkg

import (
	"errors"
	"github.com/cilium/ebpf"
)

func LoadPinnedMap(loadedMap **ebpf.Map, name string, isIngress bool) error {
        // Get container's full ID
        cgroupId := GetContainerID(name)
        if len(cgroupId) == 0 {
                return errors.New("Invalid container name or id!\n")
        }

	var path string
	pinPath := bpfPath + cgroupId
	if isIngress {
		path = pinPath + "/igs_map"
	}else{
		path = pinPath + "/egs_map"
	}

	ret, err := ebpf.LoadPinnedMap(path, nil)
        if err != nil {
                return err
        }

	*loadedMap = ret
	return nil
}
