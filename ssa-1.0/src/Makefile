ssa-objs := tls_sock_data.o tls_common.o tls_inet.o tls_inet6.o netlink.o loader.o
obj-m += ssa.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
