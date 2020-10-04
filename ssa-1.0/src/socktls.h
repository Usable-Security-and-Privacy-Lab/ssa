#ifndef SOCKTLS_H
#define SOCKTLS_H

/* Protocol */
#define IPPROTO_TLS     (715 % 255)


/* socket options checked for in the kernel */
#define TLS_TRUSTED_PEER_CERTIFICATES     87
#define TLS_CERTIFICATE_CHAIN             88
#define TLS_PRIVATE_KEY                   89
#define TLS_ID                            96


/* Address types */

/*
#define AF_HOSTNAME     43

struct host_addr {
        unsigned char name[255];
};


struct sockaddr_host {
    sa_family_t sin_family;
    unsigned short sin_port;
    struct host_addr sin_addr;
};
 */


#endif
