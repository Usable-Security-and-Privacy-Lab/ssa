#ifndef NETLINK_H
#define NETLINK_H

#include <linux/socket.h>

// Attributes
enum {
    SSA_NL_A_UNSPEC,
    SSA_NL_A_ID,
    SSA_NL_A_BLOCKING,
    SSA_NL_A_FAMILY,
    SSA_NL_A_SOCKADDR_INTERNAL,
    SSA_NL_A_SOCKADDR_EXTERNAL,
    SSA_NL_A_SOCKADDR_REMOTE,
    SSA_NL_A_OPTLEVEL,
    SSA_NL_A_OPTNAME,
    SSA_NL_A_OPTVAL,
    SSA_NL_A_RETURN,
    SSA_NL_A_PAD,
    __SSA_NL_A_MAX,
};

#define SSA_NL_A_MAX (__SSA_NL_A_MAX - 1)

// Operations
enum {
    SSA_NL_C_UNSPEC,
    SSA_NL_C_SOCKET_NOTIFY,
    SSA_NL_C_SETSOCKOPT_NOTIFY,
    SSA_NL_C_GETSOCKOPT_NOTIFY,
    SSA_NL_C_BIND_NOTIFY,
    SSA_NL_C_CONNECT_NOTIFY,
    SSA_NL_C_LISTEN_NOTIFY,
    SSA_NL_C_ACCEPT_NOTIFY,
    SSA_NL_C_CLOSE_NOTIFY,
    SSA_NL_C_RETURN,
    SSA_NL_C_LISTEN_ERR,
    SSA_NL_C_DATA_RETURN,
    SSA_NL_C_HANDSHAKE_RETURN,
    __SSA_NL_C_MAX,
};

#define SSA_NL_C_MAX (__SSA_NL_C_MAX - 1)

// Multicast group
enum ssa_nl_groups {
        SSA_NL_NOTIFY,
};

int register_netlink(void);
void unregister_netlink(void);

int send_socket_notification(u64 id, unsigned short family, int port_id);
int send_setsockopt_notification(u64 id, int level, int optname, void* optval, int optlen, int port_id);
int send_getsockopt_notification(u64 id, int level, int optname, int port_id);
int send_bind_notification(u64 id, struct sockaddr *int_addr, int int_addrlen, struct sockaddr *ext_addr, int ext_addrlen, int port_id);
int send_connect_notification(u64 id, struct sockaddr *int_addr, int int_addrlen, struct sockaddr *rem_addr, int rem_addrlen, int blocking, int port_id);
int send_listen_notification(u64 id, struct sockaddr *int_addr, int int_addrlen, struct sockaddr *ext_addr, int ext_addrlen, int port_id);
int send_accept_notification(u64 id, struct sockaddr *int_addr, int int_addrlen, int port_id);
int send_close_notification(u64 id, int port_id);

#endif
