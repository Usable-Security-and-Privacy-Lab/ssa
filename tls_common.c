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
#include "socktls.h"
#include "tls_common.h"
#include "tls_inet.h"
#include "netlink.h"

#define HASH_TABLE_BITSIZE	9
#define MAX_HOST_LEN		255

/* Helpers */
int get_id(tls_sock_data_t* sock_data, char __user *optval, int* __user optlen);
char* get_absolute_path(char* rpath, int* rpath_len);
char* kgetcwd(char* buffer, int buflen);

static DEFINE_HASHTABLE(tls_sock_data_table, HASH_TABLE_BITSIZE);
static DEFINE_SPINLOCK(tls_sock_data_table_lock);

/**
 * Finds a socket option in the hash table
 * @param	key - A pointer to the sock struct related to the socket option
 * @return	TLS socket data associated with key, if any. If not found, returns NULL
 */
tls_sock_data_t* get_tls_sock_data(unsigned long key) {

	tls_sock_data_t* it;

	hash_for_each_possible(tls_sock_data_table, it, hash, key) {
		if (it->key == key) {
			return it;
		}
	}
	return NULL;
}


unsigned long get_randomizer(void) {

    static unsigned long randomizer;
    static int rand_number_set = 0;
    static DEFINE_SPINLOCK(randomizer_lock);

    if (!rand_number_set) { /* to make sure spinlock isn't used unnecessarily */
        spin_lock(&randomizer_lock);
        if (!rand_number_set) { /* to make sure `randomizer` only ever set once */
            randomizer = get_random_long();
            rand_number_set = 1;
        }
        spin_unlock(&randomizer_lock);
    }

    return randomizer;
}


unsigned long get_sock_id(struct socket* sock) {

    return ((unsigned long) sock) ^ get_randomizer();
}


void put_tls_sock_data(unsigned long key, struct hlist_node* hash) {

	spin_lock(&tls_sock_data_table_lock);
	hash_add(tls_sock_data_table, hash, key);
	spin_unlock(&tls_sock_data_table_lock);
}

void rem_tls_sock_data(struct hlist_node* hash) {

	spin_lock(&tls_sock_data_table_lock);
	hash_del(hash);
	spin_unlock(&tls_sock_data_table_lock);
}

void tls_setup(void) {

	register_netlink();
	hash_init(tls_sock_data_table);
}

void tls_cleanup(void) {
        int bkt;
        tls_sock_data_t* it;
        struct hlist_node tmp;
        struct hlist_node* tmpptr = &tmp;

        spin_lock(&tls_sock_data_table_lock);
        hash_for_each_safe(tls_sock_data_table, bkt, tmpptr, it, hash) {
		/*if (it->int_addr.sa_family == AF_INET) {
			(*ref_tcp_v4_destroy_sock)(it->sk);
		}
		else {
			(*ref_unix_release)((it->sk)->sk_socket);
		}*/
            hash_del(&it->hash);
		    kfree(it);
        }
        spin_unlock(&tls_sock_data_table_lock);

	unregister_netlink();

	return;
}


void report_return(unsigned long key, int ret) {

	tls_sock_data_t* sock_data;
	sock_data = get_tls_sock_data(key);
	//BUG_ON(sock_data == NULL);
	if (sock_data == NULL) {
		printk(KERN_ERR "sock_data null: %s %d \n",__FUNCTION__,__LINE__);
		return;
	}
	sock_data->response = ret;
	complete(&sock_data->sock_event);
	return;
}

void report_data_return(unsigned long key, char* data, unsigned int len) {
	tls_sock_data_t* sock_data;
	sock_data = get_tls_sock_data(key);
	//BUG_ON(sock_data == NULL);
	if (sock_data == NULL) {
		printk(KERN_ERR "sock_data null: %s %d \n",__FUNCTION__,__LINE__);
		return;
	}
	sock_data->rdata = kmalloc(len, GFP_KERNEL);
	if (sock_data->rdata == NULL) {
		printk(KERN_ALERT "Failed to create memory for getsockopt return\n");
	}
	memcpy(sock_data->rdata, data, len);
	sock_data->rdata_len = len;
	/* set success if this callback is used.
	 * The report_return case is for errors
	 * and simple statuses */
	sock_data->response = 0;
	complete(&sock_data->sock_event);
	return;
}

void report_listening_err(unsigned long key) {

	tls_sock_data_t* sock_data;
	sock_data = get_tls_sock_data(key);
	//BUG_ON(sock_data == NULL);
	if (sock_data == NULL) {
		return;
	}
	sock_data->is_error = 1;
	return;
}

void report_handshake_finished(unsigned long key, int response) {

	tls_sock_data_t* sock_data;
	sock_data = get_tls_sock_data(key);
	//BUG_ON(sock_data == NULL);
	if (sock_data == NULL) {
		printk(KERN_ERR "sock_data null: %s %d \n",__FUNCTION__,__LINE__);
		return;
	}
	sock_data->response = response;
	if (sock_data->async_connect == 1) {
		inet_trigger_connect(sock_data->associated_socket, sock_data->daemon_id);
        sock_data->async_connect = 0;
        
	}
	else {
		complete(&sock_data->sock_event);
	}
	return;
}


int tls_common_setsockopt(tls_sock_data_t* sock_data, struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen, setsockopt_t orig_func) {

	int timeout_val = RESPONSE_TIMEOUT;
    int ret;
	char* koptval;

	if (optval == NULL) {
		return -EINVAL;
	}
	if (optlen == 0) {
		return -EINVAL;
	}
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
	if (wait_for_completion_timeout(&sock_data->sock_event, timeout_val) == 0) {
		/* Let's lie to the application if the daemon isn't responding */
		return -ENOBUFS;
	}
	if (sock_data->response != 0) {
		return sock_data->response;
	}

	/* We only get here if the daemonside setsockopt succeeded */
	if (level != IPPROTO_TLS) {
		/* Now we do the same thing to the application socket, if applicable */
		if (orig_func != NULL) {
			return orig_func(sock, level, optname, optval, optlen);
		}
		return -EOPNOTSUPP;
	}
	return 0;
}


int tls_common_getsockopt(tls_sock_data_t* sock_data, struct socket *sock, 
            int level, int optname, char __user *optval, 
            int __user *optlen, getsockopt_t orig_func) {
	int len;
	if (get_user(len, optlen)) {
		return -EFAULT;
	}

	if (level != IPPROTO_TLS) {
		if (orig_func != NULL) {
			return orig_func(sock, level, optname, optval, optlen);
		}
		return -EOPNOTSUPP;
	}

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


int get_id(tls_sock_data_t* sock_data, char __user *optval, int* __user optlen) {
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

char* get_full_comm(char* buffer, int buflen) {
	char* path_ptr;
	struct file* exe_file;
	struct mm_struct* mm;
	mm = get_task_mm(current);
	if (mm == NULL) {
		return NULL;
	}

	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file == NULL) {
		up_read(&mm->mmap_sem);
		return NULL;
	}

	path_ptr = d_path(&exe_file->f_path, buffer, buflen);

	up_read(&mm->mmap_sem);
	return path_ptr;
}

char* kgetcwd(char* buffer, int buflen) {
	char* path_ptr;
	struct path pwd;
	get_fs_pwd(current->fs, &pwd);

	path_ptr = d_path(&pwd, buffer, buflen);
	return path_ptr;
}

char* get_absolute_path(char* rpath, int* rpath_len) {
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
