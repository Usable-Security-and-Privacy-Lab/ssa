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