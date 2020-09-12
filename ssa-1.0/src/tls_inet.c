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

static unsigned int balancer = 0;
static DEFINE_SPINLOCK(load_balance_lock);

static struct proto_ops ref_inet_stream_ops;
static struct proto ref_tcp_prot;

/* TLS functions for INET ops */
int tls_inet_init_sock(struct sock *sk);
int tls_inet_release(struct socket* sock);
int tls_inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int tls_inet_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int tls_inet_listen(struct socket *sock, int backlog);
int tls_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern);
int tls_inet_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int tls_inet_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);

unsigned int tls_inet_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait);

/* We don't need sendmsg, recvmsg, poll, etc here because we're using the native socket functions */

int set_tls_prot_inet_stream(struct proto* tls_prot, struct proto_ops* tls_proto_ops) {
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
	tls_proto_ops->bind = tls_inet_bind;
	tls_proto_ops->connect = tls_inet_connect;
	tls_proto_ops->listen = tls_inet_listen;
	tls_proto_ops->accept = tls_inet_accept;
	tls_proto_ops->setsockopt = tls_inet_setsockopt;
	tls_proto_ops->getsockopt = tls_inet_getsockopt;
    tls_proto_ops->poll = tls_inet_poll;

	return 0;
}

void inet_stream_cleanup(void) {
	percpu_counter_destroy(&tls_orphan_count);
	percpu_counter_destroy(&tls_sockets_allocated);
	return;
}

int tls_inet_init_sock(struct sock *sk) {

    struct sockaddr_in* int_addr;
    tls_sock_data_t* sock_data;
    char comm[NAME_MAX];
    char* comm_ptr;
    int ret;

    sock_data = kcalloc(1, sizeof(tls_sock_data_t), GFP_KERNEL);
    if (sock_data == NULL) {
        printk(KERN_ALERT "kmalloc failed in tls_inet_init_sock\n");
        return -ENOMEM;
    }

    int_addr = (struct sockaddr_in*) &sock_data->int_addr;
    int_addr->sin_family = AF_INET;
    int_addr->sin_port = 0;
    int_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sock_data->key = get_sock_id(sk->sk_socket);
    sock_data->associated_socket = sk->sk_socket;

    spin_lock(&load_balance_lock);
    sock_data->daemon_id = DAEMON_START_PORT + balancer;
    //printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_data->daemon_id);
    balancer = (balancer + 1) % NUM_DAEMONS;
    spin_unlock(&load_balance_lock);

    init_completion(&sock_data->sock_event);
	ret = ref_tcp_prot.init(sk);
    if (ret != 0) {
        kfree(sock_data);
        return ret;
    }

    put_tls_sock_data(sock_data->key, &sock_data->hash);

    comm_ptr = get_full_comm(comm, NAME_MAX);

    ret = send_socket_notification(sock_data->key, comm_ptr, sock_data->daemon_id);
    if (ret != 0)
        goto err;

    ret = wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
    if (ret == 0) {
        ret = -ENOTCONN;
        goto err;
    }
    /* We're not checking return values here because init_sock always returns 0 */
    
    return 0;
err:

    if (sock_data != NULL) {
        rem_tls_sock_data(&sock_data->hash);
        kfree(sock_data);
    }

    return ret;
}

int tls_inet_release(struct socket* sock) {
    
    unsigned long sock_id = get_sock_id(sock);
	tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);

	if (sock_data == NULL) {
		/* We're not treating this particular socket.*/
		return ref_inet_stream_ops.release(sock);
	}

	send_close_notification(sock_id, sock_data->daemon_id);
	//wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
	rem_tls_sock_data(&sock_data->hash);
	kfree(sock_data);
	return ref_inet_stream_ops.release(sock);
}

int tls_inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {

	int ret;
    unsigned long sock_id = get_sock_id(sock);
	tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
	/* We disregard the address the application wants to bind to in favor
	 * of one assigned by the system (using sin_port = 0 on localhost),
	 * so that we can have the TLS wrapper daemon bind to the actual one */

	ret = ref_inet_stream_ops.bind(sock, &sock_data->int_addr, addr_len);
	/* We only want to continue if the internal socket bind succeeds */
	if (ret != 0) {
		printk(KERN_ALERT "INET bind failed\n");
		return ret;
	}

	/* We can use the port number now because inet_bind will have set
	 * it for us */
	((struct sockaddr_in*)&sock_data->int_addr)->sin_port = inet_sk(sock->sk)->inet_sport;

	send_bind_notification(get_sock_id(sock), &sock_data->int_addr,
			(struct sockaddr*)uaddr, sock_data->daemon_id);
	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
    }
    if (sock_data->response != 0)
        return sock_data->response;


    sock_data->is_bound = 1;
    sock_data->int_addrlen = addr_len;
    sock_data->ext_addr = *uaddr;
    sock_data->ext_addrlen = addr_len;
    return 0;
}



int tls_inet_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags) {

	struct sockaddr_in reroute_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	struct sockaddr_in int_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
	int ret, blocking;

    /* Save original destination address information */
	sock_data->rem_addr = (struct sockaddr)(*uaddr);
	sock_data->rem_addrlen = addr_len;

	/* Pre-emptively bind the source port so we can register it before remote
	 * connection. We only do this if the application hasn't explicitly called
	 * bind already */
	if (sock_data->is_bound == 0) {
		ref_inet_stream_ops.bind(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));
		int_addr.sin_port = inet_sk(sock->sk)->inet_sport;
		memcpy(&sock_data->int_addr, &int_addr, sizeof(int_addr));
		sock_data->is_bound = 1;
		sock_data->int_addrlen = sizeof(int_addr);
	}

	blocking = !(flags & O_NONBLOCK);

	/* If we've been interrupted (in a previous call to connect)
	 * then we're currently being called again and shouldn't
	 * double send connect notifies or wait */
	if (sock_data->interrupted == 1) {
		reroute_addr.sin_port = htons(sock_data->daemon_id);
		ret = ref_inet_stream_ops.connect(sock, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr), flags);
		if (ret != 0) {
			if (ret == -ERESTARTSYS) { /* Interrupted by signal, transparently restart */
				sock_data->interrupted = 1;
			}
			else {
				sock_data->interrupted = 0;
			}
		}

		return ret;
	}

	/* Connect notifications and waiting should only happen the first time for
	 * any connection attempt */

	if (blocking == 0) {
		sock_data->async_connect = 1;

		send_connect_notification(sock_id, &sock_data->int_addr, uaddr, blocking,
			sock_data->daemon_id);
		printk(KERN_ALERT "nonblocking wait going\n");
		if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
			return -EHOSTUNREACH;
		}

        /* here we do a cheeky snipe on the socket state to make poll think it's connecting */
        printk(KERN_INFO "sk_state: %i\n", sock->sk->sk_state);
        
		if (sock_data->response != 0) {
			sock->sk->sk_err = -sock_data->response;
            
			return sock_data->response;
		}

		return 0;
	}

	/* Blocking case */
	send_connect_notification(sock_id, &sock_data->int_addr, uaddr, blocking,
			sock_data->daemon_id);
	if (wait_for_completion_timeout(&sock_data->sock_event, HANDSHAKE_TIMEOUT) == 0)
		return -EHOSTUNREACH;

	if (sock_data->response != 0)
		return sock_data->response;

	reroute_addr.sin_port = htons(sock_data->daemon_id);
	ret = ref_inet_stream_ops.connect(sock, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr), flags);
	if (ret != 0) {
		if (ret == -ERESTARTSYS) { /* Interrupted by signal, transparently restart */
			sock_data->interrupted = 1;
		}
		return ret;
	}

	return 0;
}

int tls_inet_listen(struct socket *sock, int backlog) {

    struct sockaddr_in int_addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    unsigned long sock_id = get_sock_id(sock);
	tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);


	if (sock_data->is_bound == 0) {
		ref_inet_stream_ops.bind(sock, (struct sockaddr*)&int_addr, sizeof(int_addr));
		int_addr.sin_port = inet_sk(sock->sk)->inet_sport;
		memcpy(&sock_data->int_addr, &int_addr, sizeof(int_addr));
		sock_data->int_addrlen = sizeof(int_addr);
		sock_data->is_bound = 1;
	}
	send_listen_notification(sock_id, 
			(struct sockaddr*)&sock_data->int_addr,
		        (struct sockaddr*)&sock_data->ext_addr,
			sock_data->daemon_id);

	if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -EADDRINUSE;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}

	return ref_inet_stream_ops.listen(sock, backlog);
}

int tls_inet_accept(struct socket *sock, struct socket *newsock, int flags, bool kern) {

    unsigned long listen_sock_id = get_sock_id(sock);
	tls_sock_data_t* listen_sock_data = get_tls_sock_data(listen_sock_id);
	tls_sock_data_t* sock_data = NULL;
	int ret;

	if (listen_sock_data == NULL)
		return -EBADF;

	/* We need to make sure the daemon's listener didn't keel over and die */
	if (listen_sock_data->is_error) {
		return -EBADFD; /* it keeled over and died on us */
	}

	ret = ref_inet_stream_ops.accept(sock, newsock, flags, kern);
	if (ret != 0)
		return ret;
	
	if ((sock_data = kmalloc(sizeof(tls_sock_data_t), GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "kmalloc failed in tls_inet_accept\n");
		return -ENOMEM;
	}

	memset(sock_data, 0, sizeof(tls_sock_data_t));

	sock_data->daemon_id = listen_sock_data->daemon_id;
	sock_data->key = get_sock_id(newsock);
	init_completion(&sock_data->sock_event);
	put_tls_sock_data(sock_data->key, &sock_data->hash);

	((struct sockaddr_in*)&sock_data->int_addr)->sin_family = AF_INET;
	((struct sockaddr_in*)&sock_data->int_addr)->sin_port = inet_sk(newsock->sk)->inet_dport;
	((struct sockaddr_in*)&sock_data->int_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	send_accept_notification(sock_data->key, &sock_data->int_addr, sock_data->daemon_id);
	if (wait_for_completion_interruptible(&sock_data->sock_event) != 0)
		return -EINTR;
	return sock_data->response;
}

int tls_inet_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {

    unsigned long sock_id = get_sock_id(sock);
	tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
	if (sock_data == NULL)
		return -EBADF;
	
	return tls_common_setsockopt(sock_data, sock, level, optname, optval, optlen, ref_inet_stream_ops.setsockopt);
}

int tls_inet_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {

    unsigned long sock_id = get_sock_id(sock);
	tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    if (sock_data == NULL)
        return -EBADF;

    return tls_common_getsockopt(sock_data, sock, level, optname, optval, optlen, ref_inet_stream_ops.getsockopt);
}

void inet_trigger_connect(struct socket* sock, int daemon_id) {

	struct sockaddr_in reroute_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

    printk(KERN_INFO "sk_state in trigger_connect: %i\n", sock->sk->sk_state);
    printk(KERN_INFO "sk_err in trigger_connect: %i\n", sock->sk->sk_err);


    reroute_addr.sin_port = htons(daemon_id);
	ref_inet_stream_ops.connect(sock, ((struct sockaddr*)&reroute_addr), sizeof(reroute_addr), O_NONBLOCK);
    printk(KERN_INFO "async connect sk->state: %i\n", sock->sk->sk_state);
    printk(KERN_INFO "async connect sk->err: %i\n", sock->sk->sk_err);

	printk(KERN_ALERT "Async connect done\n");
	return;
}


unsigned int tls_inet_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait) {

    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);

    if (sock_data->async_connect == 1) {
        printk(KERN_INFO "called tls_inet_poll on async_connecting socket\n");
        sock_poll_wait(file, sock, wait);
        
        /* TODO: include 'smp_rmb();' here?? any other functions? */
        return 0;
    }
    else {
        printk(KERN_INFO "called tls_inet_poll on non-async socket\n");
        printk(KERN_INFO "socket state:%i\n", sock->sk->sk_state);
        return ref_inet_stream_ops.poll(file, sock, wait);
    }
}