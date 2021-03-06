# Attach a network filter to a cgroup
To apply to a container, change cgroupPath in attach.go
- /sys/fs/cgroup/system.slice/docker-xxx.scope
```bash
# compile and attach ebpf program to cgroup
make
./attach
```

# Test
- ctn1	172.17.0.2
- ctn2	172.17.0.3 run a service on port 80

## Enable tracing process
```bash
./trace
```

## Test ingress rule attached to ctn2
```bash
docker exec -ti ctn1 sh
/ # curl 172.17.0.3
```
## Test egress rule attached to ctn2
```bash
docker exec -ti ctn2 sh
/ # ping 8.8.4.4
PING 8.8.4.4 (8.8.4.4): 56 data bytes
ping: sendto: Operation not permitted
```

# detach program
```bash
./detach
make clean
```
