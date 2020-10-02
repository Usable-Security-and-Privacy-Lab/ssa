#include <linux/random.h>

#include "netlink.h"
#include "tls_common.h"
#include "tls_sock_data.h"


#define HASH_TABLE_BITSIZE	9
#define MAX_HOST_LEN		255

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
        tls_trigger_connect(sock_data->associated_socket, sock_data->daemon_id);
        sock_data->async_connect = 0;
        
    } else {
        complete(&sock_data->sock_event);
    }
    return;
}

