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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/capability.h>
#include <linux/cpumask.h>

#include "tls_common.h"
#include "tls_inet.h"
#include "tls_inet6.h"
#include "socktls.h"

#define DRIVER_AUTHOR   "Mark O'Neill <mark@markoneill.name> and Nick Bonner <j.nick.bonner@gmail.com>"
#define DRIVER_DESC	    "A loadable TLS module to give TLS functionality to the POSIX socket API"


MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);


/* The IPv4 TLS protocol structures to be filled and registered */
static struct proto tls_prot;
static struct proto_ops tls_proto_ops;
static struct net_protocol tls_protocol;
static struct inet_protosw tls_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TLS,
	.prot		= &tls_prot,
	.ops		= &tls_proto_ops,
	.flags 		= INET_PROTOSW_ICSK
};


/* The IPv6 TLS protocol structures to be filled and registered */

static struct proto tlsv6_prot;
static struct proto_ops tlsv6_proto_ops;

static struct inet6_protocol tlsv6_protocol;
static struct inet_protosw tlsv6_stream_protosw = {
    .type       = SOCK_STREAM,
    .protocol   = IPPROTO_TLS,
    .prot       = &tlsv6_prot,
    .ops        = &tlsv6_proto_ops,
    .flags      = INET_PROTOSW_ICSK
};


static int __init ssa_init(void) {

    unsigned long ipv4_protocol_ptr, ipv6_protocol_ptr;
    int ret;

	printk(KERN_INFO "Initializing Secure Socket API module\n");
	printk(KERN_INFO "Found %u CPUs\n", nr_cpu_ids);

	/* initialize our global data structures for TLS handling */
	tls_setup();

	/* Obtain referencess to desired TLS handling functions */
	tls_protos_init(&tls_prot, &tls_proto_ops);
    tlsv6_protos_init(&tlsv6_prot, &tlsv6_proto_ops);

    

	/* Initialize the TLS protocol */
	/* XXX Do we really NOT want to allocate cache space here? Why is 2nd param 0? */
	ret = proto_register(&tls_prot, 0);
	if (ret == 0) {
		printk(KERN_INFO "TLS protocol registration was successful\n");
	} else {
		printk(KERN_ALERT "TLS Protocol registration failed\n");
		goto err;
	}

    ret = proto_register(&tlsv6_prot, 0);
    if (ret == 0) {
		printk(KERN_INFO "TLS protocol registration was successful\n");
	} else {
		printk(KERN_ALERT "TLS Protocol registration failed\n");
		goto err;
	}

	/*
	 * Retrieve the non-exported tcp_protocol struct address location
	 * and verify that it was found. If it fails, unregister the protocol
	 * and exit the module initialization.
	 */
	ipv4_protocol_ptr = kallsyms_lookup_name("tcp_protocol");
	if (ipv4_protocol_ptr == 0) {
		printk(KERN_ALERT "kallsyms_lookup_name failed to retrieve tcp_protocol address\n");
		goto out_proto_unregister;
	}

    ipv6_protocol_ptr = kallsyms_lookup_name("tcpv6_protocol");
    if (ipv6_protocol_ptr == 0) {
		printk(KERN_ALERT "kallsyms_lookup_name failed to retrieve tcp_protocol address\n");
		goto out_proto_unregister;
	}

	/* Create a copy of the tcp_protocol net_protocol and register it with IPPROTO_TLS.
	   We borrow these operations because they suit our needs. Modify them later if
	   necessary through our local copy. */
	tls_protocol = *((struct net_protocol*) ipv4_protocol_ptr);
    tlsv6_protocol = *((struct inet6_protocol*) ipv6_protocol_ptr);

	ret = inet_add_protocol(&tls_protocol, IPPROTO_TLS);
	if (ret == 0) {
		printk(KERN_INFO "Protocol insertion in inet_protos[] was successful\n");
	} else {
		printk(KERN_ALERT "Protocol insertion in inet_protos[] failed\n");
		goto out_proto_unregister;
	}

    ret = inet6_add_protocol(&tlsv6_protocol, IPPROTO_TLS);
    if (ret == 0) {
		printk(KERN_INFO "Protocol insertion in inet_protos[] was successful\n");
	} else {
		printk(KERN_ALERT "Protocol insertion in inet_protos[] failed\n");
		goto out_proto_unregister;
	}

	inet_register_protosw(&tls_stream_protosw);
    inet6_register_protosw(&tlsv6_stream_protosw);

    printk(KERN_INFO "Initialized Secure Socket API module successfully\n");


    /* TODO: set up IPv6 here */
    return 0;


out_proto_unregister:
    proto_unregister(&tls_prot);
    proto_unregister(&tlsv6_prot);

err:
    return ret;
}



static void __exit ssa_exit(void) {

	tls_protos_cleanup();
    tlsv6_protos_cleanup();

	/* Unregister the protocols and structs in the reverse order they were registered */
	inet_del_protocol(&tls_protocol, IPPROTO_TLS);
	inet_unregister_protosw(&tls_stream_protosw);

    inet6_del_protocol(&tlsv6_protocol, IPPROTO_TLS);
    inet6_unregister_protosw(&tlsv6_stream_protosw);

	/* Set these pointers to NULL to avoid deleting tcp_prot's shared memory */
	tls_prot.slab = NULL;
	tls_prot.rsk_prot = NULL;
	tls_prot.twsk_prot = NULL;

    tlsv6_prot.slab = NULL;
    tlsv6_prot.rsk_prot = NULL;
    tlsv6_prot.twsk_prot = NULL;

	proto_unregister(&tls_prot);
    proto_unregister(&tlsv6_prot);

	printk(KERN_INFO "Secure Socket API module removed\n");
	/* Free TLS socket handling data */
	tls_cleanup();
}

module_init(ssa_init);
module_exit(ssa_exit);
