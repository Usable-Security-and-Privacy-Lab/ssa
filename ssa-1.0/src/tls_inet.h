#ifndef TLS_INET_H
#define TLS_INET_H

#include <net/sock.h>
#include <linux/net.h>


extern struct proto_ops ref_inet_stream_ops;
extern struct proto ref_tcp_prot;


void tls_protos_init(struct proto* tls_prot, struct proto_ops* tls_proto_ops);
void tls_protos_cleanup(void);

#endif /* TLS_INET_H */
