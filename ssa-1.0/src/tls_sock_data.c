/*
 * Secure Socket API - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017-2018, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


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
struct tls_sock_data *get_tls_sock_data(u64 key)
{
    struct tls_sock_data *it;

    hash_for_each_possible(tls_sock_data_table, it, hash, key) {
        if (it->key == key) {
            return it;
        }
    }

    return NULL;
}

u64 get_randomizer(void)
{
    static u64 randomizer;
    static u8 rand_set = 0;
    static DEFINE_SPINLOCK(randomizer_lock);

    if (!rand_set) { /* to make sure spinlock isn't used unnecessarily */
        spin_lock(&randomizer_lock);
        if (!rand_set) { /* to make sure `randomizer` only ever set once */
            randomizer = get_random_long();
            rand_set = 1; /* WARNING: race conditions if placed before */
        }
        spin_unlock(&randomizer_lock);
    }

    return randomizer;
}

u64 get_sock_id(struct socket *sock)
{
    return ((u64) sock) ^ get_randomizer();
}


void put_tls_sock_data(u64 key, struct hlist_node *hash)
{
    spin_lock(&tls_sock_data_table_lock);
    hash_add(tls_sock_data_table, hash, key);
    spin_unlock(&tls_sock_data_table_lock);

    return;
}

void rem_tls_sock_data(struct hlist_node *hash)
{
    spin_lock(&tls_sock_data_table_lock);
    hash_del(hash);
    spin_unlock(&tls_sock_data_table_lock);

    return;
}

void tls_setup(void)
{
    register_netlink();
    hash_init(tls_sock_data_table);

    return;
}

void tls_cleanup(void)
{
    struct tls_sock_data *it;
    struct hlist_node tmp;
    struct hlist_node *tmpptr = &tmp;
    int bkt;

    spin_lock(&tls_sock_data_table_lock);
    hash_for_each_safe(tls_sock_data_table, bkt, tmpptr, it, hash) {

    /*
    if (it->int_addr.sa_family == AF_INET) {
        (*ref_tcp_v4_destroy_sock)(it->sk);
    }
    else {
        (*ref_unix_release)((it->sk)->sk_socket);
    }
     */

        hash_del(&it->hash);
        kfree(it);
    }
    spin_unlock(&tls_sock_data_table_lock);

    unregister_netlink();

    return;
}


int report_return(u64 key, int ret)
{
    struct tls_sock_data *sock_data;

    sock_data = get_tls_sock_data(key);
    if (sock_data == NULL) {
        pr_err("SSA: Netlink notification received for unknown socket\n");
        return -EINVAL; /* Causes problems otherwise */
    }

    sock_data->response = ret;
    complete(&sock_data->sock_event);

    return 0;
}

int report_data_return(u64 key, char *data, unsigned int len)
{
    struct tls_sock_data *sock_data;
    
    sock_data = get_tls_sock_data(key);
    if (sock_data == NULL) {
        pr_err("SSA: Netlink data notification received for unknown socket\n");
        return -EINVAL;
    }

    sock_data->rdata = kmalloc(len, GFP_KERNEL);
    if (sock_data->rdata == NULL) {
        pr_alert("SSA: Allocation for getsockopt data failed\n");
        return -ENOMEM;
    }

    memcpy(sock_data->rdata, data, len);
    sock_data->rdata_len = len;
    /* set success if this callback is used.
     * The report_return case is for errors
     * and simple statuses */
    sock_data->response = 0;
    complete(&sock_data->sock_event);

    return 0;
}

int report_listening_err(u64 key)
{
    struct tls_sock_data *sock_data;

    sock_data = get_tls_sock_data(key);
    if (sock_data == NULL) {
        pr_err("SSA: Netlink listener notification received for unknown socket\n");
        return -EINVAL;
    }

    sock_data->flags |= TLS_SOCK_ERROR;
    
    return 0;
}

int report_handshake_finished(u64 key, int response)
{
    struct tls_sock_data *sock_data;
    int err = -EINVAL;

    sock_data = get_tls_sock_data(key);
    if (sock_data == NULL) {
        pr_err("SSA: Netlink handshake notification received for unknown socket\n");
        goto out;
    }

    sock_data->response = response;

    if (sock_data->flags & TLS_SOCK_ASYNC_CONNECT) {
        err = tls_trigger_connect(sock_data->sock, 
                                  sock_data->daemon_id);
        sock_data->flags &= ~TLS_SOCK_ASYNC_CONNECT;
        
    } else {
        complete(&sock_data->sock_event);
        err = 0;
    }

out:
    return err;
}

