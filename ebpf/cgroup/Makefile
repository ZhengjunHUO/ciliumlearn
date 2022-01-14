CCOMPILER = clang
GOCOMPILER = go
CGO_ENV = CGO_ENABLED=0
STRIP = llvm-strip

.PHONY: all
.DEFAULT_GOAL := build_prog

build_ebpf: bpf.c
	$(CCOMPILER) -O2 -target bpf -c $^ -o bpf.o -I../../header_kernel_5.4
	$(STRIP) -g bpf.o

build_prog: build_ebpf attach.go trace.go detach.go translate.go
	$(CGO_ENV) $(GOCOMPILER) build -o attach attach.go translate.go
	$(CGO_ENV) $(GOCOMPILER) build -o trace trace.go translate.go
	$(CGO_ENV) $(GOCOMPILER) build -o detach detach.go translate.go

clean:
	$(RM) bpf.o attach trace detach
