#ifndef TLS_INET6_H
#define TLS_INET6_H

#include <linux/net.h>



extern struct proto_ops ref_inet6_stream_ops;
extern struct proto ref_tcpv6_prot;



int tlsv6_protos_init(struct proto *prot, struct proto_ops *proto_ops);
void tlsv6_protos_cleanup(void);




#endif