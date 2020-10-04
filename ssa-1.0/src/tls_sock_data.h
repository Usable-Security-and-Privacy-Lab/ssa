#ifndef TLS_SOCK_DATA_H
#define TLS_SOCK_DATA_H

#include <linux/completion.h>
#include <linux/hashtable.h>
#include <linux/socket.h>

/* This struct holds additional data needed by our TLS sockets */
/* This structure only works because sockaddr is going
 * to be bigger than our sockaddr_un addresses, which are
 * always abstract (and thus 6 bytes + sizeof(sa_family_t))
 */
struct tls_sock_data {

    struct hlist_node hash;
    struct socket *sock;
    u64 key;
    int daemon_id; /* userspace daemon to which the socket is assigned */
    u8 flags;

    struct sockaddr_storage ext_addr;
    int ext_addrlen;
    struct sockaddr_storage int_addr;
    int int_addrlen;
    struct sockaddr_storage rem_addr;
    int rem_addrlen;

    struct completion sock_event;
    int response;
    char *rdata; /* returned data from asynchronous callback */
    unsigned int rdata_len; /* length of data returned from async callback */

};

enum {
    TLS_SOCK_INTERRUPTED = 1 << 0,
    TLS_SOCK_BOUND = 1 << 1,
    TLS_SOCK_ERROR = 1 << 2,
    TLS_SOCK_ASYNC_CONNECT = 1 << 3,
};



/* Hashing */
struct tls_sock_data *get_tls_sock_data(u64 key);
void put_tls_sock_data(u64 key, struct hlist_node *hash);
void rem_tls_sock_data(struct hlist_node *hash);

u64 get_sock_id(struct socket *sock);


/* Allocation of hashmap/netlink socket */
void tls_setup(void);
void tls_cleanup(void);


/* Data reporting callbacks */
int report_return(u64 key, int ret);
int report_listening_err(u64 key);
int report_data_return(u64 key, char *data, unsigned int len);
int report_handshake_finished(u64 key, int response);


#endif