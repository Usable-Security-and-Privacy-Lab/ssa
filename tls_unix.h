#ifndef TLS_UNIX_H
#define TLS_UNIX_H

#include <net/sock.h>
#include <linux/net.h>

int set_tls_prot_unix_stream(struct proto* tls_prot, struct proto_ops* tls_proto_ops);

#endif /* TLS_UNIX_H */