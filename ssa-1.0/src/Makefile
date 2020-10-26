ssa-objs := loader.o netlink.o tls_common.o tls_inet.o tls_inet6.o tls_sock_data.o
obj-m += ssa.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
