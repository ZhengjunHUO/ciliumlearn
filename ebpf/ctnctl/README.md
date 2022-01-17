- cgroup v2 is required (container's cgroup is: /sys/fs/cgroup/system.slice/docker-xxx.scope/)

## Build
```bash
make
cp ctnctl /usr/local/bin/ctnctl
```

## Run
```bash
ctnctl -h
```

## Cleanup
```bash
make clean 
```
