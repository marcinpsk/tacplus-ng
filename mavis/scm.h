/*
 * smc.h
 *
 * (C)2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: scm.h,v 1.2 2011/08/21 13:04:50 marc Exp marc $
 *
 */

#ifndef __SCM_H__
#define __SCM_H__

#include "misc/net.h"

enum scm_token { SCM_DONE = 0, SCM_KEEPALIVE, SCM_MAY_DIE, SCM_DYING, SCM_BAD_CFG, SCM_MAX,
    SCM_ACCEPT, SCM_UDPDATA, SCM_UDPDONE,
};

struct scm_data {
    enum scm_token type;
    int count;
};

struct scm_data_accept {
    enum scm_token type;
    u_int tls_versions;
    int aaa_protocol;
#define SCM_FLAG_HAPROXY 1
#define SCM_FLAG_RADACCT 2
#define SCM_FLAG_TLSPSK  4
#define SCM_FLAG_TLSAUTO  8
#define SCM_FLAG_UDPNEW 16		// SCM_UDPDATA: spawnd has no worker for the client yet
    u_int flags;
#define SCM_REALM_SIZE 16
    char realm[SCM_REALM_SIZE];
    int socktype;		// SOCK_STREAM, SOCK_SEQPACKET; SOCK_DGRAM
    int protocol;		// AF_INET, AF_INET6, ...
};

#define SCM_UDP_DATA_MAX 65535	// the largest UDP payload

// A UDP client, as spawnd and the worker name it.
struct scm_udp_client {
    int listener;		// spawnd's number of the listener
    sockaddr_union local;	// the destination address of the datagrams of the client
    sockaddr_union peer;
};

// The order of clients for spawnd and the worker. An IPv6 address compares with its scope, the interface of a link-local address.
int scm_udp_client_cmp(const struct scm_udp_client *, const struct scm_udp_client *);

// A datagram from spawnd. The descriptor of the listener comes with the first datagram of each listener.
struct scm_data_udp {
    enum scm_token type;
    u_int tls_versions;
    int aaa_protocol;
    u_int flags;
    char realm[SCM_REALM_SIZE];
    struct scm_udp_client client;
    u_int id;			// spawnd's number of the client, new with SCM_FLAG_UDPNEW
    u_int data_len;
    u_char data[] __attribute__((aligned(8)));
};

// A first datagram that is a DTLS handshake record: a new DTLS client starts with a ClientHello.
int scm_udp_dtls(const u_char *, size_t);

#define SCM_SECRET "SPAWND_SECRET"	// environment of a worker: the random secret of its spawnd, in hex
#define SCM_SECRET_LEN 32

// To spawnd: the worker has no context for this client.
struct scm_data_udpdone {
    enum scm_token type;
    u_int id;
    struct scm_udp_client client;
};

int scm_send_msg(int, struct scm_data *, int);
int scm_recv_msg(int, struct scm_data_accept *, size_t, int *);
int fakescm_send_msg(int, struct scm_data *, int);
int fakescm_recv_msg(int, struct scm_data_accept *, size_t, int *);
void scm_main(int, char **, char **);
void scm_fatal(void);

#endif				/* __SCM_H__ */
