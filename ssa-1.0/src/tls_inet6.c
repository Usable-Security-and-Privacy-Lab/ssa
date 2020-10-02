#include <linux/kallsyms.h>
#include <linux/percpu_counter.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>

#include "netlink.h"
#include "tls_common.h"
#include "tls_inet6.h"


static atomic_long_t tlsv6_memory_allocated;
static struct percpu_counter tlsv6_orphan_count;
static struct percpu_counter tlsv6_sockets_allocated;


struct proto_ops ref_inet6_stream_ops;
struct proto ref_tcpv6_prot;


int tls_inet6_init_sock(struct sock *sk);
int tls_inet6_release(struct socket* sock);



int tlsv6_protos_init(struct proto* prot, struct proto_ops* proto_ops)
{
    struct proto_ops *inet6_ops_ptr = NULL;
    struct proto *tcpv6_prot_ptr = NULL;

    tcpv6_prot_ptr = (struct proto*) kallsyms_lookup_name("tcpv6_prot");
    if (tcpv6_prot_ptr == NULL) {
        printk(KERN_ALERT "Couldn't find reference IPv6 proto");
        return -1;
    }

    /* We share operations with IPv6 TCP for transport to daemon */
    ref_tcpv6_prot = *tcpv6_prot_ptr;
    *prot = *tcpv6_prot_ptr;

	/* Guessing what the TLS-unique things should be here */
	strcpy(prot->name, "TLS");
	prot->owner = THIS_MODULE;
	prot->inuse_idx = 0;
	prot->memory_allocated = &tlsv6_memory_allocated;
	prot->orphan_count = &tlsv6_orphan_count;
	prot->sockets_allocated = &tlsv6_sockets_allocated;
	percpu_counter_init(&tlsv6_orphan_count, 0, GFP_KERNEL);
	percpu_counter_init(&tlsv6_sockets_allocated, 0, GFP_KERNEL);

	/* Keep all tcp_prot functions except the following */
	prot->init = tls_inet6_init_sock;


    inet6_ops_ptr = (struct proto_ops*) kallsyms_lookup_name("inet6_stream_ops");
    if (inet6_ops_ptr == NULL) {
        printk(KERN_ALERT "Couldn't find reference IPv6 stream ops");
        return -1;
    }

	ref_inet6_stream_ops = *inet6_ops_ptr;
	*proto_ops = *inet6_ops_ptr;

	
	proto_ops->owner = THIS_MODULE;

	/* Keep all inet_stream_ops except the following */
    
	proto_ops->release = tls_inet6_release;
	proto_ops->bind = tls_bind;
	proto_ops->connect = tls_connect;
	proto_ops->listen = tls_listen;
	proto_ops->accept = tls_accept;
	proto_ops->setsockopt = tls_setsockopt;
	proto_ops->getsockopt = tls_getsockopt;
    proto_ops->poll = tls_poll;
    

	return 0;
}


void tlsv6_protos_cleanup(void)
{
	percpu_counter_destroy(&tlsv6_orphan_count);
	percpu_counter_destroy(&tlsv6_sockets_allocated);
	return;
}



int tls_inet6_init_sock(struct sock *sk)
{
    return tls_common_init_sock(sk, AF_INET6);
}

int tls_inet6_release(struct socket* sock)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    /* WARNING: DO NOT attempt to dereference sock->sk */

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

    return ref_inet6_stream_ops.release(sock);
}

