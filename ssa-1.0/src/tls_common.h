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

typedef int (*setsockopt_t)(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
typedef int (*getsockopt_t)(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);


/* Socket functionality */
int tls_common_setsockopt(tls_sock_data_t* sock_data, struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen, setsockopt_t orig_func);
int tls_common_getsockopt(tls_sock_data_t* sock_data, struct socket *sock, int level, int optname, char __user *optval, int __user *optlen, getsockopt_t orig_func);

/* Misc */
char* get_full_comm(char* buffer, int buflen);

#endif /* TLS_COMMON_H */
