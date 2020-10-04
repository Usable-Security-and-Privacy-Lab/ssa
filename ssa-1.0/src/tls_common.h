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
#ifndef TLS_COMMON_H
#define TLS_COMMON_H

#include <linux/hashtable.h>
#include <linux/completion.h>
#include <linux/socket.h>
#include <linux/net.h>

#include "tls_sock_data.h"


#define RESPONSE_TIMEOUT	HZ*10
#define HANDSHAKE_TIMEOUT	HZ*180
#define DAEMON_START_PORT	8443
#define NUM_DAEMONS		1


int tls_common_init_sock(struct sock *sk, sa_family_t family);

int tls_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int tls_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int tls_listen(struct socket *sock, int backlog);
int tls_accept(struct socket *sock, struct socket *newsock, int flags, bool kern);
int tls_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
int tls_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);
unsigned int tls_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait);

int tls_trigger_connect(struct socket *sock, int daemon_id);


#endif /* TLS_COMMON_H */
