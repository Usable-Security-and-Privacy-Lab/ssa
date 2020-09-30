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
typedef struct tls_sock_data {

    struct socket* associated_socket;
	unsigned long key;
        struct hlist_node hash;
	struct sockaddr ext_addr;
	int ext_addrlen;
	struct sockaddr int_addr;
	int int_addrlen;
	struct sockaddr rem_addr;
	int rem_addrlen;
	int is_bound;
	int is_error;
	int async_connect;
	int interrupted; 
	struct completion sock_event;
	int response;
	char* rdata; /* returned data from asynchronous callback */
	unsigned int rdata_len; /* length of data returned from async callback */
	int daemon_id; /* userspace daemon to which the socket is assigned */
} tls_sock_data_t;



/* Hashing */
tls_sock_data_t* get_tls_sock_data(unsigned long key);
void put_tls_sock_data(unsigned long key, struct hlist_node* hash);
void rem_tls_sock_data(struct hlist_node* hash);

unsigned long get_sock_id(struct socket* sock);


/* Allocation of hashmap/netlink socket */
void tls_setup(void);
void tls_cleanup(void);


/* Data reporting callbacks */
void report_return(unsigned long key, int ret);
void report_listening_err(unsigned long key);
void report_data_return(unsigned long key, char* data, unsigned int len);
void report_handshake_finished(unsigned long key, int response);


#endif