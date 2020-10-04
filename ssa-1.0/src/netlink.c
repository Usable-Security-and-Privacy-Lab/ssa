#include <net/netlink.h>
#include <net/genetlink.h>

#include "netlink.h"
#include "tls_common.h"

int nl_fail(struct sk_buff *skb, struct genl_info *info);
int daemon_cb(struct sk_buff *skb, struct genl_info *info);
int daemon_listen_err_cb(struct sk_buff *skb, struct genl_info *info);
int daemon_data_cb(struct sk_buff *skb, struct genl_info *info);
int daemon_handshake_cb(struct sk_buff *skb, struct genl_info *info);

/* netlink still validates everything but range when NLA_VALIDATE_NONE is set */
static const struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
    [SSA_NL_A_ID] = {
        .type = NLA_U64,
        .len = 0,
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_BLOCKING] = {
        .type = NLA_U32,
        .len = 0,
        .validation_type = NLA_VALIDATE_RANGE,
        .min = 0,
        .max = 1,
    },
    [SSA_NL_A_FAMILY] = {
        .type = NLA_U16,
        .len = 0,
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_SOCKADDR_INTERNAL] = {
        .type = NLA_BINARY,
        .len = sizeof(struct sockaddr_storage),
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_SOCKADDR_EXTERNAL] = {
        .type = NLA_BINARY,
        .len = sizeof(struct sockaddr_storage),
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_SOCKADDR_REMOTE] = {
        .type = NLA_BINARY,
        .len = sizeof(struct sockaddr_storage),
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_OPTLEVEL] = {
        .type = NLA_U32,
        .len = 0,
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_OPTNAME] = {
        .type = NLA_U32,
        .len = USHRT_MAX, /* TODO: should this be more strict? */
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_OPTVAL] = {
        .type = NLA_BINARY,
        .len = 0,
        .validation_type = NLA_VALIDATE_NONE,
    },
    [SSA_NL_A_RETURN] = {
        .type = NLA_U32,
        .len = 0,
        .validation_type = NLA_VALIDATE_NONE,
    },
};

static struct genl_ops ssa_nl_ops[] = {
    {
        .cmd = SSA_NL_C_SOCKET_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_SETSOCKOPT_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_GETSOCKOPT_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_BIND_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_CONNECT_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_LISTEN_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_ACCEPT_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_CLOSE_NOTIFY,
        .flags = GENL_ADMIN_PERM,
        .doit = nl_fail,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_RETURN,
        .flags = GENL_ADMIN_PERM,
        .doit = daemon_cb,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_LISTEN_ERR,
        .flags = GENL_ADMIN_PERM,
        .doit = daemon_listen_err_cb,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_DATA_RETURN,
        .flags = GENL_ADMIN_PERM,
        .doit = daemon_data_cb,
        .dumpit = NULL,
    },
    {
        .cmd = SSA_NL_C_HANDSHAKE_RETURN,
        .flags = GENL_ADMIN_PERM,
        .doit = daemon_handshake_cb,
        .dumpit = NULL,
    },
};

static const struct genl_multicast_group ssa_nl_grps[] = {
    [SSA_NL_NOTIFY] = { .name = "notify", },
};

static struct genl_family ssa_nl_family = {
    .name = "SSA",
    .version = 1,
    .maxattr = SSA_NL_A_MAX,
    .policy = ssa_nl_policy,
    .ops = ssa_nl_ops,
    .mcgrps = ssa_nl_grps,
    .n_ops = ARRAY_SIZE(ssa_nl_ops),
    .n_mcgrps = ARRAY_SIZE(ssa_nl_grps),
    .module = THIS_MODULE,
};

int nl_fail(struct sk_buff *skb, struct genl_info *info)
{
    pr_alert("SSA: Received a send-only netlink message\n");

    return -EINVAL;
}

/**
 * This is the callback function that is triggered when netlink_notify_kernel()
 * is called from the daemon.
 */
int daemon_cb(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr *na;
    int err = -EINVAL;
    int response;
    u64 key;

    if (info == NULL) {
        pr_alert("SSA: Netlink notify message info is null\n");
        goto out;
    }

    if ((na = info->attrs[SSA_NL_A_ID]) == NULL) {
        pr_alert("SSA: Netlink notify message missing ID value\n");
        goto out;
    }

    key = nla_get_u64(na);

    if ((na = info->attrs[SSA_NL_A_RETURN]) == NULL) {
        pr_alert("SSA: Netlink notify message lacks return value\n");
        goto out;
    }

    response = nla_get_u32(na);

    err = report_return(key, response);

out:
    return err;
}

int daemon_listen_err_cb(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr *na;
    int err = -EINVAL;
    u64 key;

    if (info == NULL) {
        pr_alert("SSA: Netlink listen_err message info is null \n");
        goto out;
    }

    if ((na = info->attrs[SSA_NL_A_ID]) == NULL) {
        pr_alert("SSA: Netlink listen_err message lacks ID value\n");
        goto out;
    }

    key = nla_get_u64(na);

    err = report_listening_err(key);

out:
    return err;
}

/**
 * This is the callback function for when netlink_send_and_notify_kernel is
 * called from the daemon.
 */
int daemon_data_cb(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr *na;
    u64 key;
    unsigned int len;
    char* data;
    int err = -EINVAL;

    if (info == NULL) {
        pr_alert("SSA: Netlink data message info is null\n");
        goto out;
    }

    if ((na = info->attrs[SSA_NL_A_ID]) == NULL) {
        pr_alert("SSA: Netlink data message lacks ID value\n");
        goto out;
    }

    key = nla_get_u64(na);

    if ((na = info->attrs[SSA_NL_A_OPTVAL]) == NULL) {
        pr_alert("SSA: Netlink data message lacks data value\n");
        goto out;
    }

    data = nla_data(na);
    len = nla_len(na);

    err = report_data_return(key, data, len);

out:
    return err;
}

/**
 * This is the callback function that is triggered when
 * netlink_handshake_notify_kernel() is called from the daemon.
 */
int daemon_handshake_cb(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr *na;
    u64 key;
    int response;
    int err = -EINVAL;

    if (info == NULL) {
        pr_alert("SSA: Netlink handshake message info was null\n");
        goto out;
    }

    if ((na = info->attrs[SSA_NL_A_ID]) == NULL) {
        pr_alert("SSA: Netlink handshake message lacks ID value\n");
        goto out;
    }

    key = nla_get_u64(na);

    if ((na = info->attrs[SSA_NL_A_RETURN]) == NULL) {
        pr_alert("SSA: Netlink handshake message lacks return value\n");
        goto out;
    }

    response = nla_get_u32(na);
    
    err = report_handshake_finished(key, response);

out:
    return err;
}

int register_netlink(void)
{
    return genl_register_family(&ssa_nl_family);
}

void unregister_netlink(void)
{
    genl_unregister_family(&ssa_nl_family);
    
    return;
}

/**
 * Forms and sends a netlink notification to the daemon to create a new
 * socket and assign it the given id.
 */
int send_socket_notification(u64 id, unsigned short family, int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + nla_total_size(sizeof(family));
    struct sk_buff *skb = NULL;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [socket notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_SOCKET_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message head [socket notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err) {
        pr_alert("SSA: Failed to add ID to message [socket notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_FAMILY, sizeof(family), &family);
    if (err) {
        pr_alert("SSA: Failed to add family to message [socket notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err) {
        pr_alert("SSA: Failed to unicast [socket notify]\n (%d)", err);
        return -ENOTCONN;
    }

    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to perform a setsockopt
 * command on the socket with given id.
 */
int send_setsockopt_notification(u64 id, int level, int optname, void* optval, 
                                 int optlen, int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + 2 * nla_total_size(sizeof(int))
                 + nla_total_size(optlen);
    struct sk_buff *skb;
    void *msg_head;
    int err;
    
    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [setsockopt notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, 
                           SSA_NL_C_SETSOCKOPT_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message head [setsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err) {
        pr_alert("SSA: Failed to add ID to message [setsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_OPTLEVEL, sizeof(int), &level);
    if (err) {
        pr_alert("SSA: Failed to add optlevel to message [setsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_OPTNAME, sizeof(int), &optname);
    if (err) {
        pr_alert("SSA: Failed to add optname to message [setsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_OPTVAL, optlen, optval);
    if (err) {
        pr_alert("SSA: Failed to add optval to message [setsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err) {
        pr_alert("SSA: Failed to unicast message (%d) [setsockopt notify]\n", err);
        return -ENOTCONN;
    }

    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to perform a getsockopt
 * command on the socket with given id.
 */
int send_getsockopt_notification(u64 id, int level, int optname, int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + 2 * nla_total_size(sizeof(int));
    struct sk_buff *skb;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [getsockopt notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, 
                           SSA_NL_C_GETSOCKOPT_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message head [getsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err != 0) {
        pr_alert("SSA: Failed to add ID to message [getsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_OPTLEVEL, sizeof(int), &level);
    if (err != 0) {
        pr_alert("SSA: Failed to add optlevel to message [getsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_OPTNAME, sizeof(int), &optname);
    if (err != 0) {
        pr_alert("SSA: Failed to add optname to message [getsockopt notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err != 0) {
        pr_alert("SSA: Failed to unicast message (%d) [getsockopt notify]\n", err);
        return -1;
    }
    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to bind the socket
 * specified by id to a given address.
 */
int send_bind_notification(u64 id, 
                           struct sockaddr *int_addr, int int_addrlen, 
                           struct sockaddr *ext_addr, int ext_addrlen, 
                           int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + nla_total_size(int_addrlen)
                 + nla_total_size(ext_addrlen);
    struct sk_buff *skb;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [bind notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_BIND_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message header [bind notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err != 0) {
        printk(KERN_ALERT "SSA: Failed to add ID to message [bind notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, int_addrlen, int_addr);
    if (err != 0) {
        pr_alert("SSA: Failed to add int_addr to message [bind notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_EXTERNAL, ext_addrlen, ext_addr);
    if (err != 0) {
        pr_alert("SSA: Failed to add ext_addr to message [bind notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err != 0) {
        pr_alert("SSA: Failed to unicast message (%d) [bind notify]\n", err);
        return -ENOTCONN;
    }

    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to connect the socket
 * specified by id to a given address.
 */
int send_connect_notification(u64 id, 
                              struct sockaddr *int_addr, int int_addrlen, 
                              struct sockaddr *rem_addr, int rem_addrlen, 
                              int blocking, int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + nla_total_size(int_addrlen)
                 + nla_total_size(rem_addrlen) 
                 + nla_total_size(sizeof(int));
    struct sk_buff *skb;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [connect notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, 
                           SSA_NL_C_CONNECT_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message header [connect notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err != 0) {
        pr_alert("SSA: Failed to add ID to message [connect notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, int_addrlen, int_addr);
    if (err != 0) {
        pr_alert("SSA: Failed to add int_addr to message [connect notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_REMOTE, rem_addrlen, rem_addr);
    if (err != 0) {
        pr_alert("SSA: Failed to add ext_addr to message [connect notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_BLOCKING, sizeof(blocking), &blocking);
    if (err != 0) {
        pr_alert("SSA: Failed to add blocking to message [connect notify]\n");
        nlmsg_free(skb);
        return -1;
    }
    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err != 0) {
        pr_alert("SSA: Failed to unicast message (%d) [connect notify]\n", err);
        return -ENOTCONN;
    }

    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to set the socket to
 * listen for incoming connections on its port and address.
 */
int send_listen_notification(u64 id, 
                             struct sockaddr *int_addr, int int_addrlen, 
                             struct sockaddr *ext_addr, int ext_addrlen, 
                             int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + nla_total_size(int_addrlen)
                 + nla_total_size(ext_addrlen);
    struct sk_buff *skb;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [listen notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, 
                           SSA_NL_C_LISTEN_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message header [listen notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err != 0) {
        pr_alert("SSA: Failed to add ID to message [listen notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, int_addrlen, int_addr);
    if (err != 0) {
        pr_alert("SSA: FAiled to add int_addr to message [listen notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_EXTERNAL, ext_addrlen, ext_addr);
    if (err != 0) {
        pr_alert("SSA: Failed to add ext_addr to message [listen notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err != 0) {
        pr_alert("SSA: Failed to unicast message (%d) [listen notify]\n", err);
        return -ENOTCONN;
    }

    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to accept a new
 * connection on the listening socket specified by id.
 */
int send_accept_notification(u64 id, struct sockaddr *int_addr, int int_addrlen, 
                             int port_id)
{
    int msg_size = nla_total_size(sizeof(id)) + nla_total_size(int_addrlen)
                 + nla_total_size(sizeof(int));
    struct sk_buff *skb;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [accept notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_ACCEPT_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message header [accept notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err != 0) {
        pr_alert("SSA: Failed to add ID to message [accept notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, int_addrlen, int_addr);
    if (err != 0) {
        pr_alert("SSA: Failed to add int_addr to message [accept notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);

    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err != 0) {
        pr_alert("SSA: Failed to unicast message (%d) [accept notify]\n", err);
        return -ENOTCONN;
    }

    return 0;
}

/**
 * Forms and sends a netlink notification to the daemon to close the socket
 * specified by id.
 */
int send_close_notification(u64 id, int port_id)
{
    int msg_size = nla_total_size(sizeof(id));
    struct sk_buff *skb;
    void *msg_head;
    int err;

    skb = genlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        pr_alert("SSA: Failed to allocate message [close notify]\n");
        return -ENOMEM;
    }

    msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_CLOSE_NOTIFY);
    if (msg_head == NULL) {
        pr_alert("SSA: Failed to prepare message header [close notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    err = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
    if (err != 0) {
        pr_alert("SSA: Failed to add ID to message [close notify]\n");
        nlmsg_free(skb);
        return -ENOBUFS;
    }

    genlmsg_end(skb, msg_head);
    err = genlmsg_unicast(&init_net, skb, port_id);
    if (err != 0) {
        pr_alert("SSA: Failed to unicast message (%d) [close notify]\n", err);
        return -ENOTCONN;
    }

    return 0;
}
