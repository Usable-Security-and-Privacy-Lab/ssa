#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/completion.h>
#include <linux/string.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/limits.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include "tls_inet.h"
#include "tls_common.h"
#include "netlink.h"


static atomic_long_t tls_memory_allocated;
static struct percpu_counter tls_orphan_count;
static struct percpu_counter tls_sockets_allocated;



struct proto_ops ref_inet_stream_ops;
struct proto ref_tcp_prot;


int tls_inet_init_sock(struct sock *sk);
int tls_inet_release(struct socket* sock);


void tls_protos_init(struct proto* tls_prot, struct proto_ops* tls_proto_ops)
{
    /* We share operations with TCP for transport to daemon */
    *tls_prot = tcp_prot;
    ref_tcp_prot = tcp_prot;

    /* Guessing what the TLS-unique things should be here */
    strcpy(tls_prot->name, "TLS");
    tls_prot->owner = THIS_MODULE;
    tls_prot->inuse_idx = 0;
    tls_prot->memory_allocated = &tls_memory_allocated;
    tls_prot->orphan_count = &tls_orphan_count;
    tls_prot->sockets_allocated = &tls_sockets_allocated;
    percpu_counter_init(&tls_orphan_count, 0, GFP_KERNEL);
    percpu_counter_init(&tls_sockets_allocated, 0, GFP_KERNEL);

    /* Keep all tcp_prot functions except the following */
    tls_prot->init = tls_inet_init_sock;

    *tls_proto_ops = inet_stream_ops;
    ref_inet_stream_ops = inet_stream_ops;
    
    tls_proto_ops->owner = THIS_MODULE;

    /* Keep all inet_stream_ops except the following */
    tls_proto_ops->release = tls_inet_release;
    tls_proto_ops->bind = tls_bind;
    tls_proto_ops->connect = tls_connect;
    tls_proto_ops->listen = tls_listen;
    tls_proto_ops->accept = tls_accept;
    tls_proto_ops->setsockopt = tls_setsockopt;
    tls_proto_ops->getsockopt = tls_getsockopt;
    tls_proto_ops->poll = tls_poll;

    return;
}


void tls_protos_cleanup(void)
{
    percpu_counter_destroy(&tls_orphan_count);
    percpu_counter_destroy(&tls_sockets_allocated);
    return;
}


int tls_inet_init_sock(struct sock *sk)
{
    return tls_common_init_sock(sk, AF_INET);
}


int tls_inet_release(struct socket* sock)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    /* WARNING: DO NOT attempt to dereference sock->sk within this function */

    printk(KERN_INFO "release called");

    if (sock_data != NULL) {
        send_close_notification(sock_id, sock_data->daemon_id);
        //wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
        printk(KERN_INFO "close notification sent...");

        rem_tls_sock_data(&sock_data->hash);
        printk(KERN_INFO "removed socket data from hashmap...");
        kfree(sock_data);
        printk(KERN_INFO "freed socket data...");
    }

    printk(KERN_INFO "now calling tcp_ops.release()...");

    return ref_inet_stream_ops.release(sock);
}