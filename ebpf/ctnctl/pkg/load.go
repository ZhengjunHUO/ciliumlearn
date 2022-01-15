package pkg

import (
	"errors"
	"github.com/cilium/ebpf"
)

//func LoadPinnedMap(loadedMap *ebpf.Map, name string, isIngress bool) error {
func LoadPinnedMap(name string, isIngress bool) (*ebpf.Map, error) {
        // Get container's full ID
        cgroupId := GetContainerID(name)
        if len(cgroupId) == 0 {
                //return errors.New("Invalid container name or id!\n")
                return nil, errors.New("Invalid container name or id!\n")
        }

	var path string
	pinPath := bpfPath + cgroupId
	if isIngress {
		path = pinPath + "/igs_map"
	}else{
		path = pinPath + "/egs_map"
	}

	loadedMap, err := ebpf.LoadPinnedMap(path, nil)
        if err != nil {
                return nil, err
        }

	return loadedMap, nil
}
