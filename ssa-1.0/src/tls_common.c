#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/ctype.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/fs_struct.h>

#include <net/inet_sock.h>

#include "netlink.h"
#include "socktls.h"
#include "tls_common.h"
#include "tls_inet.h"
#include "tls_inet6.h"
#include "tls_sock_data.h"


#define HASH_TABLE_BITSIZE	9
#define MAX_HOST_LEN		255


static DEFINE_SPINLOCK(load_balance_lock);
static unsigned int balancer = 0;


struct sockaddr_storage get_loopback_address(sa_family_t family);
int get_loopback_addrlen(sa_family_t family);
struct proto_ops get_proto_ops(struct sock *sk);
void set_port(struct sockaddr_storage *addr, u16 port);


/* Helpers */
int get_id(tls_sock_data_t* sock_data, char __user *optval, int* __user optlen);
char* get_absolute_path(char* rpath, int* rpath_len);
char* kgetcwd(char* buffer, int buflen);


int tls_common_init_sock(struct sock *sk, sa_family_t family)
{
    tls_sock_data_t* sock_data;
    int ret;


    sock_data = kcalloc(1, sizeof(tls_sock_data_t), GFP_KERNEL);
    if (sock_data == NULL) {
        printk(KERN_ALERT "kmalloc failed in tls_init_sock\n");
        return -ENOMEM;
    }

    /* Assigning the loopback address to connect to */
    sock_data->int_addr = get_loopback_address(family);
    sock_data->int_addrlen = get_loopback_addrlen(family);

    sock_data->associated_socket = sk->sk_socket;
    sock_data->key = get_sock_id(sk->sk_socket);


    spin_lock(&load_balance_lock);
    sock_data->daemon_id = DAEMON_START_PORT + balancer;
    //printk(KERN_INFO "Assigning new socket to daemon %d\n", sock_data->daemon_id);
    balancer = (balancer + 1) % NUM_DAEMONS;
    spin_unlock(&load_balance_lock);

    init_completion(&sock_data->sock_event);

    if (family == AF_INET)
        ret = ref_tcp_prot.init(sk);
    else 
        ret = ref_tcpv6_prot.init(sk);

    if (ret != 0) {
        kfree(sock_data);
        return ret;
    }

    printk(KERN_INFO "af_family: %s", (sk->sk_family == AF_INET) ? "AF_INET" : "AF_INET6");

    put_tls_sock_data(sock_data->key, &sock_data->hash);

    ret = send_socket_notification(sock_data->key, family, sock_data->daemon_id);
    if (ret != 0)
        goto err;

    ret = wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT);
    if (ret == 0) {
        ret = -ENOTCONN;
        goto err;
    }
    
    return 0; /* TODO: test to see if this is right? Was 0... */
err:

    if (sock_data != NULL) {
        rem_tls_sock_data(&sock_data->hash);
        kfree(sock_data);
    }

    return ret;
}


int tls_bind(struct socket *sock, struct sockaddr *addr, int addrlen)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);
    int ret;

    printk(KERN_INFO "af_family: %s", (sock->sk->sk_family == AF_INET) ? "AF_INET" : "AF_INET6");

    /* We disregard the address the application wants to bind to in favor
     * of one assigned by the system (using sin_port = 0 on localhost),
     * so that we can have the TLS wrapper daemon bind to the actual one */

    ret = tcp_ops.bind(sock, (struct sockaddr*) &sock_data->int_addr, sock_data->int_addrlen);
    /* We only want to continue if the internal socket bind succeeds */
    if (ret != 0) {
        printk(KERN_ALERT "Internal bind failed\n");
        return ret;
    }

    /* We can use the port number now because inet_bind will have set
     * it for us */
    set_port(&sock_data->int_addr, inet_sk(sock->sk)->inet_sport);


    send_bind_notification(sock_id, (struct sockaddr*) &sock_data->int_addr, sock_data->int_addrlen,
                addr, addrlen, sock_data->daemon_id);
    if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
        /* Let's lie to the application if the daemon isn't responding */
        return -EADDRINUSE;
    }

    if (sock_data->response != 0)
        return sock_data->response;

    sock_data->is_bound = 1;
    memcpy(&sock_data->ext_addr, addr, addrlen);
    sock_data->ext_addrlen = addrlen;

    return 0;
}


int tls_connect(struct socket *sock, struct sockaddr *rem_addr, int rem_addrlen, int flags)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);
    sa_family_t family = sock->sk->sk_family;

    struct sockaddr_storage reroute_addr = get_loopback_address(family);
    int reroute_addrlen = get_loopback_addrlen(family);

    struct sockaddr_storage int_addr = get_loopback_address(family);
    int int_addrlen = get_loopback_addrlen(family);
    
    int ret, blocking;

    /* Save original destination address information */
    sock_data->rem_addr = *((struct sockaddr_storage*) rem_addr);
    sock_data->rem_addrlen = rem_addrlen;

    /* Pre-emptively bind the source port so we can register it before remote
     * connection. We only do this if the application hasn't explicitly called
     * bind already */
    if (sock_data->is_bound == 0) {
        tcp_ops.bind(sock, (struct sockaddr*) &int_addr, int_addrlen);

        set_port(&int_addr, inet_sk(sock->sk)->inet_sport);

        memcpy(&sock_data->int_addr, &int_addr, int_addrlen);
        sock_data->int_addrlen = int_addrlen;

        sock_data->is_bound = 1;
    }

    blocking = !(flags & O_NONBLOCK);

    /* If we've been interrupted (in a previous call to connect)
     * then we're currently being called again and shouldn't
     * double send connect notifies or wait */
    if (sock_data->interrupted == 1) {
        set_port(&reroute_addr, htons(sock_data->daemon_id));

        ret = tcp_ops.connect(sock, (struct sockaddr*) &reroute_addr, reroute_addrlen, flags);
        if (ret != 0) {
            if (ret == -ERESTARTSYS) /* Interrupted by signal, transparently restart */
                sock_data->interrupted = 1;
            else
                sock_data->interrupted = 0;
        }

        return ret;
    }

    /* Connect notifications and waiting should only happen the first time for
     * any connection attempt */

    if (blocking == 0) {
        sock_data->async_connect = 1;

        send_connect_notification(sock_id, (struct sockaddr*) &sock_data->int_addr, sock_data->int_addrlen, 
                rem_addr, rem_addrlen, blocking, sock_data->daemon_id);
        printk(KERN_ALERT "nonblocking wait going\n");
        if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
            return -EHOSTUNREACH;
        }

        /* here we do a cheeky snipe on the socket state to make poll think it's connecting */
        printk(KERN_INFO "sk_state: %i\n", sock->sk->sk_state);
        
        if (sock_data->response != 0) {
            sock->sk->sk_err = -sock_data->response; /* TODO: do this everywhere? */
            
            return sock_data->response;
        }

        return 0;
    }

    /* Blocking case */
    send_connect_notification(sock_id, (struct sockaddr*) &sock_data->int_addr, sock_data->int_addrlen, 
                rem_addr, rem_addrlen, blocking, sock_data->daemon_id);
    if (wait_for_completion_timeout(&sock_data->sock_event, HANDSHAKE_TIMEOUT) == 0)
        return -EHOSTUNREACH;

    if (sock_data->response != 0)
        return sock_data->response;

    set_port(&reroute_addr, htons(sock_data->daemon_id));

    ret = tcp_ops.connect(sock, ((struct sockaddr*) &reroute_addr), reroute_addrlen, flags);
    if (ret != 0) {
        if (ret == -ERESTARTSYS) { /* Interrupted by signal, transparently restart */
            sock_data->interrupted = 1;
        }
        return ret;
    }

    return 0;

}


void tls_trigger_connect(struct socket* sock, int daemon_id)
{
    struct sockaddr_storage reroute_addr = get_loopback_address(sock->sk->sk_family);
    int reroute_addrlen = get_loopback_addrlen(sock->sk->sk_family);
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);

    printk(KERN_INFO "sk_state in trigger_connect: %i\n", sock->sk->sk_state);
    printk(KERN_INFO "sk_err in trigger_connect: %i\n", sock->sk->sk_err);

    set_port(&reroute_addr, htons(daemon_id));

    tcp_ops.connect(sock, ((struct sockaddr*) &reroute_addr), reroute_addrlen, O_NONBLOCK);

    printk(KERN_INFO "async connect sk->state: %i\n", sock->sk->sk_state);
    printk(KERN_INFO "async connect sk->err: %i\n", sock->sk->sk_err);

    printk(KERN_ALERT "Async connect done\n");
    return;
}



int tls_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);
    int timeout_val = RESPONSE_TIMEOUT;
    int ret;
    char* koptval;

    if (optval == NULL || optlen == 0)
        return -EINVAL;

    koptval = kmalloc(optlen, GFP_KERNEL);
    if (koptval == NULL) {
        return -ENOMEM;
    }

    if (copy_from_user(koptval, optval, optlen) != 0) {
        kfree(koptval);
        return -EFAULT;
    }

    switch (optname) {
    case TLS_TRUSTED_PEER_CERTIFICATES:
    case TLS_CERTIFICATE_CHAIN:
    case TLS_PRIVATE_KEY:

        /* We convert relative paths to absolute ones
         * here. We also skip things prefixed with '-'
         * because that denotes direct PEM encoding */
        if (koptval[0] != '-' && koptval[0] != '/') {
            koptval = get_absolute_path(koptval, &optlen);
            if (koptval == NULL) {
                return -ENOMEM;
            }
        }
        ret = 0;
        break;
    case TLS_REQUEST_PEER_AUTH:
        timeout_val = HZ*150;
        ret = 0;
        break;
    default:
        ret = 0;
        break;
    }

    /* We return early if preliminary checks during our
     * kernel-side saving of sockopts failed. No sense
     * in telling the daemon about it. */
    if (ret != 0) {
        kfree(koptval);
        return ret;
    }

    send_setsockopt_notification(sock_data->key, level, optname, koptval, optlen, sock_data->daemon_id);
    kfree(koptval);
    if (wait_for_completion_timeout(&sock_data->sock_event, timeout_val) == 0)
        return -ENOTCONN;

    if (sock_data->response != 0)
        return sock_data->response;

    /* We only get here if the daemonside setsockopt succeeded */
    if (level != IPPROTO_TLS) {
        /* Now we do the same thing to the application socket, if applicable */
        return tcp_ops.setsockopt(sock, level, optname, optval, optlen);
    }

    return 0;
}


int tls_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);
    int len;

    if (get_user(len, optlen))
        return -EFAULT;

    if (level != IPPROTO_TLS)
        return tcp_ops.getsockopt(sock, level, optname, optval, optlen);


    switch (optname) {
    case TLS_ID:
        return get_id(sock_data, optval, optlen);
    
    default:
        send_getsockopt_notification(sock_data->key, level, optname, sock_data->daemon_id);
        if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
            /* Let's lie to the application if the daemon isn't responding */
            return -ENOBUFS;
        }
        if (sock_data->response != 0) {
            return sock_data->response;
        }
        /* We set this to the minimum of actual data length and size
         * of user's buffer rather than aborting if the user one is
         * smaller because POSIX says to silently truncate in this
         * case */
        len = min_t(unsigned int, len, sock_data->rdata_len);
        if (unlikely(put_user(len, optlen))) {
            kfree(sock_data->rdata);
            sock_data->rdata = NULL;
            sock_data->rdata_len = 0;
            return -EFAULT;
        }
        if (copy_to_user(optval, sock_data->rdata, len)) {
            kfree(sock_data->rdata);
            sock_data->rdata = NULL;
            sock_data->rdata_len = 0;
            return -EFAULT;
        }
        break;
    }

    return 0;

}


 int tls_listen(struct socket *sock, int backlog)
 {

    struct proto_ops tcp_ops = get_proto_ops(sock->sk);
    struct sockaddr_storage int_addr = get_loopback_address(sock->sk->sk_family);
    int int_addrlen = get_loopback_addrlen(sock->sk->sk_family);

    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);

    printk(KERN_INFO "listen af_family: %s", (sock->sk->sk_family == AF_INET) ? "AF_INET" : "AF_INET6");

    if (sock_data->is_bound == 0) {
        tcp_ops.bind(sock, (struct sockaddr*) &int_addr, int_addrlen);

        set_port(&int_addr, inet_sk(sock->sk)->inet_sport);
        memcpy(&sock_data->int_addr, &int_addr, int_addrlen);
        sock_data->int_addrlen = int_addrlen;

        sock_data->is_bound = 1;
    }

    send_listen_notification(sock_id, 
                (struct sockaddr*) &sock_data->int_addr, sock_data->int_addrlen,
                (struct sockaddr*) &sock_data->ext_addr, sock_data->ext_addrlen,
                sock_data->daemon_id);

    if (wait_for_completion_timeout(&sock_data->sock_event, RESPONSE_TIMEOUT) == 0) {
        /* Let's lie to the application if the daemon isn't responding */
        return -EADDRINUSE;
    }

    if (sock_data->response != 0) 
        return sock_data->response;

    return tcp_ops.listen(sock, backlog);
}

int tls_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
{
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);
    unsigned long listen_sock_id = get_sock_id(sock);
    tls_sock_data_t* listen_sock_data = get_tls_sock_data(listen_sock_id);
    tls_sock_data_t* sock_data = NULL;
    int ret;

    if (listen_sock_data == NULL)
        return -EBADF;

    printk(KERN_INFO "accept af_family: %s", (sock->sk->sk_family == AF_INET) ? "AF_INET" : "AF_INET6");

    /* We need to make sure the daemon's listener didn't keel over and die */
    if (listen_sock_data->is_error)
        return -EBADFD; /* it keeled over and died on us */

    printk(KERN_INFO "about to call tcp_ops.accept()");
    ret = tcp_ops.accept(sock, newsock, flags, kern);
    if (ret != 0) {
        printk(KERN_INFO "called tcp_ops.accept(); failed");
        return ret;
    }

    printk(KERN_INFO "called tcp_ops.accept(); succeeded");

    if ((sock_data = kmalloc(sizeof(tls_sock_data_t), GFP_KERNEL)) == NULL) {
        printk(KERN_ALERT "kmalloc failed in tls_accept\n");
        return -ENOMEM;
    }

    memset(sock_data, 0, sizeof(tls_sock_data_t));

    sock_data->daemon_id = listen_sock_data->daemon_id;
    sock_data->key = get_sock_id(newsock);
    init_completion(&sock_data->sock_event);
    put_tls_sock_data(sock_data->key, &sock_data->hash);

    sock_data->int_addr = get_loopback_address(sock->sk->sk_family);
    sock_data->int_addrlen = get_loopback_addrlen(sock->sk->sk_family);
    set_port(&sock_data->int_addr, inet_sk(newsock->sk)->inet_dport);

    send_accept_notification(sock_data->key, (struct sockaddr*) &sock_data->int_addr, sock_data->int_addrlen, sock_data->daemon_id);
    if (wait_for_completion_interruptible(&sock_data->sock_event) != 0)
        return -EINTR;

    printk(KERN_INFO "made it to end of accept()");

    return sock_data->response;
}


unsigned int tls_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait)
{
    unsigned long sock_id = get_sock_id(sock);
    tls_sock_data_t* sock_data = get_tls_sock_data(sock_id);
    struct proto_ops tcp_ops = get_proto_ops(sock->sk);

    if (sock_data->async_connect == 1) {
        printk(KERN_INFO "called tls_poll on async_connecting socket\n");
        sock_poll_wait(file, sock, wait);
        
        /* TODO: include 'smp_rmb();' here?? any other functions? */
        return 0;
    } else {
        printk(KERN_INFO "called tls_poll on non-async socket\n");
        printk(KERN_INFO "socket state:%i\n", sock->sk->sk_state);

        return tcp_ops.poll(file, sock, wait);
    }
}





int get_id(tls_sock_data_t* sock_data, char __user *optval, int* __user optlen)
{
    int len;
    if (get_user(len, optlen)) {
        return -EFAULT;
    }
    len = min_t(unsigned int, len, sizeof(unsigned long));
    if (put_user(len, optlen)) {
        return -EFAULT;
    }
    if (copy_to_user(optval, &sock_data->key, len)) {
        return -EFAULT;
    }
    return 0;
}


char* kgetcwd(char* buffer, int buflen)
{
    char* path_ptr;
    struct path pwd;
    get_fs_pwd(current->fs, &pwd);

    path_ptr = d_path(&pwd, buffer, buflen);
    return path_ptr;
}

char* get_absolute_path(char* rpath, int* rpath_len)
{
    char* apath;
    char* bpath;
    int bpath_len;
    char tmp[NAME_MAX];
    apath = kmalloc(PATH_MAX, GFP_KERNEL);
    if (apath == NULL) {
        kfree(rpath);
        return NULL;
    }

    bpath = kgetcwd(tmp, NAME_MAX);
    bpath_len = strlen(bpath);
    bpath[bpath_len] = '/';
    bpath_len++;
    if ((bpath_len + (*rpath_len)) >= PATH_MAX) {
        kfree(rpath);
        return NULL;
    }
    memcpy(apath, bpath, bpath_len);
    memcpy(apath + bpath_len, rpath, *rpath_len);
    kfree(rpath);
    *rpath_len = strlen(apath)+1;
    return apath;
}



struct sockaddr_storage get_loopback_address(sa_family_t family)
{
    struct sockaddr_storage addr = {0};

    if (family == AF_INET) {
        struct sockaddr_in in_addr = {
            .sin_family = AF_INET,
            .sin_port = 0,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
        };

        memcpy(&addr, &in_addr, sizeof(in_addr));

    } else { /* family == AF_INET6 */
        struct sockaddr_in6 in6_addr = {
            .sin6_family = AF_INET6,
            .sin6_port = 0,
            .sin6_addr = IN6ADDR_LOOPBACK_INIT
        };

        memcpy(&addr, &in6_addr, sizeof(in6_addr));
    }

    return addr;
}

int get_loopback_addrlen(sa_family_t family)
{
    if (family == AF_INET)
        return sizeof(struct sockaddr_in);
    else
        return sizeof(struct sockaddr_in6);
}

void set_port(struct sockaddr_storage *addr, u16 port)
{
    if (addr->ss_family == AF_INET)
        ((struct sockaddr_in*) addr)->sin_port = port;
    else
        ((struct sockaddr_in6*) addr)->sin6_port = port;
}

struct proto_ops get_proto_ops(struct sock *sk)
{
    if (sk->sk_family == AF_INET6)
        return ref_inet6_stream_ops;
    else
        return ref_inet_stream_ops;
}