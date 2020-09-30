#ifndef TLS_INET_H
#define TLS_INET_H

#include <net/sock.h>
#include <linux/net.h>

int init_tls_protos(struct proto* tls_prot, struct proto_ops* tls_proto_ops);
void inet_stream_cleanup(void);
void inet_trigger_connect(struct socket* sock, int daemon_id);

#endif /* TLS_INET_H */
