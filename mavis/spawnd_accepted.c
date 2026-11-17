/*
 * accepted.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "spawnd_headers.h"
#include "misc/mymd5.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sysexits.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct track {
#define MD5_DIGEST_SIZE 16
    u_char digest[MD5_DIGEST_SIZE];
    int i;
    time_t expires;
    struct track *lru_prev;
    struct track *lru_next;
};

static void track_lru_remove(struct track_data *data, struct track *track)
{
    if (track->lru_prev)
	track->lru_prev->lru_next = track->lru_next;

    if (track->lru_next)
	track->lru_next->lru_prev = track->lru_prev;

    if (track == data->lru_first)
	data->lru_first = track->lru_next;

    if (track == data->lru_last)
	data->lru_last = track->lru_prev;

    track->lru_next = data->lru_first;
    data->lru_first = track;
}

static void track_lru_append(struct track_data *data, struct track *track)
{
    if (track == data->lru_first || track->lru_prev)
	track_lru_remove(data, track);
    track->lru_prev = data->lru_last;
    if (data->lru_last)
	data->lru_last->lru_next = track;
    if (!data->lru_first)
	data->lru_first = track;
    data->lru_last = track;
    track->lru_next = NULL;
    track->expires = io_now.tv_sec + data->tracking_period;
}

static int compare_track(const void *a, const void *b)
{
    return memcmp(&((struct track *) a)->digest, &((struct track *) b)->digest, MD5_DIGEST_SIZE);
}

static struct track *alloc_track(struct track_data *data)
{
    if (data->tracking_size && (!data->lru_first || data->lru_first->expires > io_now.tv_sec)) {
	int n = data->tracking_size;
#define ARRSIZE 1024
	if (n > ARRSIZE)
	    n = ARRSIZE;
#undef ARRSIZE
	data->tracking_size -= n;
	struct track *tracks = calloc(n, sizeof(struct track));
	for (int i = 1; i < n; i++) {
	    tracks[i].lru_prev = &tracks[i - 1];
	    tracks[i - 1].lru_next = &tracks[i];
	}
	tracks[n - 1].lru_next = data->lru_first;
	if (data->lru_first)
	    data->lru_first->lru_prev = &tracks[n - 1];
	if (!data->lru_last)
	    data->lru_last = &tracks[n - 1];
	data->lru_first = tracks;
    }
    struct track *track = data->lru_first;
    while (track && track->expires && track->expires < io_now.tv_sec) {
	track->expires = 0;
	track_lru_remove(data, track);
	RB_search_and_delete(data->db, track);
	track = track->lru_next;
    }

    track = data->lru_first;
    if (track && track->expires) {	// no more entries left, drop least recently used
	track->expires = 0;
	track_lru_remove(data, track);
	RB_search_and_delete(data->db, track);
    }
    if (track)
	track_lru_append(data, track);
    return track;
}

static int tracking_lookup(struct track_data *data, u_char *digest)
{
    if (data->db) {
	struct track t, *tp;
	memcpy(&t.digest, digest, MD5_DIGEST_SIZE);
	if ((tp = RB_lookup(data->db, &t))) {
	    track_lru_append(data, tp);
	    return tp->i;
	}
    }
    return -1;
}

static void spawnd_adjust_tracking_one(struct track_data *data, int old, int new)
{
    if (data->db) {
	rb_node_t *r;
	r = RB_first(data->db);
	while (r) {
	    rb_node_t *rn = RB_next(r);
	    struct track *t = RB_payload(r, struct track *);
	    if (new < 0) {
		t->expires = 0;
		track_lru_remove(data, t);
		RB_delete(data->db, r);
	    } else {
		if (t->i == old)
		    t->i = new;
	    }
	    r = rn;
	}
    }
}

void spawnd_adjust_tracking(int old, int new)
{
    for (int i = 0; i < spawnd_data.listeners_max; i++)
	if (spawnd_data.listener_arr[i]->track_data.db)
	    spawnd_adjust_tracking_one(&spawnd_data.listener_arr[i]->track_data, old, new);

    if (spawnd_data.track_data.db)
	spawnd_adjust_tracking_one(&spawnd_data.track_data, old, new);
}

struct udp_client {
    struct scm_udp_client key;
    u_int id;
    struct spawnd_context *server;
    int dtls;			// a session: it stays with a retired server, a plain client does not
};

static int compare_udp_client(const void *a, const void *b)
{
    return scm_udp_client_cmp(&((struct udp_client *) a)->key, &((struct udp_client *) b)->key);
}

static struct udp_client *udp_client_lookup(struct scm_udp_client *key)
{
    struct udp_client c = {.key = *key };
    return spawnd_data.udp_clients ? RB_lookup(spawnd_data.udp_clients, &c) : NULL;
}

static void udp_client_add(struct scm_data_udp *sd, struct spawnd_context *server, int dtls)
{
    if (!spawnd_data.udp_clients)
	spawnd_data.udp_clients = RB_tree_new(compare_udp_client, free);
    struct udp_client *c = Xcalloc(1, sizeof(struct udp_client));
    c->key = sd->client;
    c->id = sd->id;
    c->server = server;
    c->dtls = dtls;
    RB_insert(spawnd_data.udp_clients, c);
    server->udp_clients++;
}

// Plain RADIUS/UDP has no session: when its server retires, the next datagram of a client goes to another server.
void spawnd_udp_forget_plain(struct spawnd_context *server)
{
    for (rb_node_t * rbn = RB_first(spawnd_data.udp_clients), *next; rbn; rbn = next) {
	next = RB_next(rbn);
	struct udp_client *c = RB_payload(rbn, struct udp_client *);
	if (c->server == server && !c->dtls) {
	    RB_delete(spawnd_data.udp_clients, rbn);
	    server->udp_clients--;
	}
    }
}

// -1: the server is gone (a retired server without UDP clients)
int spawnd_udp_done(struct spawnd_context *server, struct scm_data_udpdone *d)
{
    struct udp_client *c = udp_client_lookup(&d->client);
    // a done message of an older client with the same address is not for this one
    if (c && c->server == server && c->id == d->id) {
	RB_search_and_delete(spawnd_data.udp_clients, c);
	server->udp_clients--;
	if (!server->retired)
	    spawnd_users_done(server, 1);
	else if (!server->udp_clients) {	// as at SCM_DYING without UDP clients
	    spawnd_cleanup_internal(server, server->fn);
	    return -1;
	}
    }
    return 0;
}

struct udp_queued {
    struct udp_queued *next;
    int fd;			// the listener descriptor to pass with the datagram, or -1
    int listener;		// index of listener_arr
    size_t len;			// of the struct scm_data_udp that follows
};

#define UDP_QUEUE_MAX (1 << 20)	// bytes that wait for one server

static void udp_queue_drop(struct spawnd_context *server)
{
    struct udp_queued *q = server->udp_queue;
    server->udp_queue = q->next;
    if (!server->udp_queue)
	server->udp_queue_last = NULL;
    server->udp_queue_len -= q->len;
    free(q);
}

void spawnd_udp_forget(struct spawnd_context *server)
{
    for (rb_node_t * rbn = RB_first(spawnd_data.udp_clients), *next; rbn; rbn = next) {
	next = RB_next(rbn);
	if (RB_payload(rbn, struct udp_client *)->server == server)
	     RB_delete(spawnd_data.udp_clients, rbn);
    }
    server->udp_clients = 0;
    while (server->udp_queue)
	udp_queue_drop(server);
    Xfree(&server->udp_listeners);
}

// The socket of the server has room again: send what waits, in order.
void spawnd_udp_flush(struct spawnd_context *server, int cur)
{
    while (server->udp_queue) {
	struct udp_queued *q = server->udp_queue;
	struct scm_data_udp *sd = (struct scm_data_udp *) (q + 1);
	if (common_data.scm_send_msg(server->fn, (struct scm_data *) sd, q->fd)) {
	    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
		return;
	    if (errno != EMSGSIZE) {
		logerr("scm_send_msg (%s:%d), pid: %d", __FILE__, __LINE__, (int) server->pid);
		spawnd_cleanup_internal(server, cur);
		return;
	    }
	    logmsg("UDP datagram of %u bytes too large for the socket to the worker, dropped", sd->data_len);
	    // the next queued datagram of the listener takes its descriptor, or the next datagram of the listener
	    if (q->fd > -1) {
		struct udp_queued *n;
		for (n = q->next; n && n->listener != q->listener; n = n->next);
		if (n)
		    n->fd = q->fd;
		else
		    server->udp_listeners[q->listener] = 0;
	    }
	    // a new client of the lost datagram has no context in the worker; when it was the last client of a retired server, the server goes
	    if (sd->flags & SCM_FLAG_UDPNEW) {
		struct scm_data_udpdone d = {.type = SCM_UDPDONE,.id = sd->id,.client = sd->client };
		udp_queue_drop(server);
		if (spawnd_udp_done(server, &d))
		    return;
		continue;
	    }
	}
	udp_queue_drop(server);
    }
    io_clr_o(common_data.io, server->fn);
}

// The first datagram of a listener (index of listener_arr) for a server takes the descriptor of the listener with it.
// 0: sent, or queued; -1: lost (UDP_QUEUE_MAX, or the datagram too large); 1: the server failed
static int udp_send(struct spawnd_context *server, struct scm_data_udp *sd, int listener)
{
    if (!server->udp_listeners)
	server->udp_listeners = Xcalloc(spawnd_data.listeners_max, 1);
    int fd = server->udp_listeners[listener] ? -1 : sd->client.listener;
    if (!server->udp_queue) {
	if (!common_data.scm_send_msg(server->fn, (struct scm_data *) sd, fd)) {
	    server->udp_listeners[listener] = 1;
	    return 0;
	}
	if (errno == EMSGSIZE) {
	    logmsg("UDP datagram of %u bytes too large for the socket to the worker, dropped", sd->data_len);
	    return -1;
	}
	if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
	    return 1;
    }
    // the socket of the server is full: the datagram waits in spawnd, up to UDP_QUEUE_MAX
    size_t len = sizeof(struct scm_data_udp) + sd->data_len;
    if (server->udp_queue_len + len > UDP_QUEUE_MAX)
	return -1;
    struct udp_queued *q = Xcalloc(1, sizeof(struct udp_queued) + len);
    q->fd = fd;
    q->listener = listener;
    q->len = len;
    memcpy(q + 1, sd, len);
    if (server->udp_queue_last)
	server->udp_queue_last->next = q;
    else
	server->udp_queue = q;
    server->udp_queue_last = q;
    server->udp_queue_len += len;
    server->udp_listeners[listener] = 1;
    io_set_o(common_data.io, server->fn);
    return 0;
}

static void tracking_register(struct track_data *data, u_char *digest, int i)
{
    if (data->tracking_period < 1)
	return;
    if (!data->db)
	data->db = RB_tree_new(compare_track, NULL);
    struct track t, *tp;
    memcpy(&t.digest, digest, MD5_DIGEST_SIZE);
    tp = RB_lookup(data->db, &t);
    if (!tp) {
	tp = alloc_track(data);
	if (!tp)
	    return;
	memcpy(tp->digest, digest, MD5_DIGEST_SIZE);
	RB_insert(data->db, tp);
    }
    tp->i = i;
}

void spawnd_accepted(struct spawnd_context *ctx, int cur)
{
    int s = -1, i, min, min_i, res, flags;
    int one = 1;
    sockaddr_union sa = { 0 };
    socklen_t sa_len = (socklen_t) sizeof(sa);
    int iteration_cur = 0;
    struct in6_addr addr;
    struct scm_data_accept *sd = NULL;
    struct scm_data_udp *sd_udp = NULL;
    int listener = -1;		// UDP: index of listener_arr

    DebugIn(DEBUG_NET);

    if (ctx->socktype == SOCK_DGRAM) {

	char buf[SCM_UDP_DATA_MAX];
	char cbuf[512];

	struct iovec iov = {
	    .iov_base = buf,
	    .iov_len = sizeof(buf)
	};

	struct msghdr msg = {
	    .msg_name = &sa,
	    .msg_namelen = sizeof(sa),
	    .msg_iov = &iov,
	    .msg_iovlen = 1,
	    .msg_flags = 0,
	    .msg_control = (caddr_t) cbuf,
	    .msg_controllen = sizeof(cbuf)
	};

	ssize_t len = Recvmsg(cur, &msg, 0);
	if (len < 1) {
	    DebugOut(DEBUG_NET);
	    return;
	}
	if (msg.msg_flags & MSG_TRUNC) {
	    char b[INET6_ADDRSTRLEN];
	    logmsg("UDP datagram from %s longer than %d bytes dropped", su_ntoa(&sa, b, (socklen_t) sizeof(b)), (int) sizeof(buf));
	    DebugOut(DEBUG_NET);
	    return;
	}

	for (listener = 0; listener < spawnd_data.listeners_max && spawnd_data.listener_arr[listener] != ctx; listener++);
	if (listener == spawnd_data.listeners_max) {
	    DebugOut(DEBUG_NET);
	    return;
	}

	sd_udp = alloca(sizeof(struct scm_data_udp) + len);
	memset(sd_udp, 0, sizeof(struct scm_data_udp));
	sd_udp->type = SCM_UDPDATA;
	sd_udp->flags = ctx->sd_flags;
	sd_udp->tls_versions = ctx->dtls_versions;
	sd_udp->aaa_protocol = ctx->aaa_protocol;
	memcpy(sd_udp->realm, ctx->tag, SCM_REALM_SIZE);
	// the descriptor names the listener: it stays the same across SIGHUP
	sd_udp->client.listener = cur;
	sd_udp->client.peer = sa;
	sd_udp->data_len = len;
	memcpy(sd_udp->data, buf, len);

	// the worker replies from the destination address of the datagram
	sockaddr_union *local_su = &sd_udp->client.local;
	local_su->sa.sa_family = sa.sa.sa_family;
	for (struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef IP_PKTINFO
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif
	    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
		memcpy(&local_su->sin.sin_addr, &((struct in_pktinfo *) CMSG_DATA(cmsg))->ipi_addr, 4);
		local_su->sa.sa_family = AF_INET;
		break;
	    }
#elif defined(IP_RECVDSTADDR)
	    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
		memcpy(&local_su->sin.sin_addr, CMSG_DATA(cmsg), 4);
		local_su->sa.sa_family = AF_INET;
		break;
	    }
#endif
#ifdef IPV6_PKTINFO
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif
	    if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
		struct in6_pktinfo *pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		memcpy(&local_su->sin6.sin6_addr, &pi->ipi6_addr, 16);
		// the interface is part of a link-local address only
		if (IN6_IS_ADDR_LINKLOCAL(&pi->ipi6_addr))
		    local_su->sin6.sin6_scope_id = pi->ipi6_ifindex;
		local_su->sa.sa_family = AF_INET6;
		break;
	    }
#endif
	}
	su_convert(local_su, sa.sa.sa_family);
	su_set_port(local_su, ctx->port);

	if (common_data.singleprocess) {
	    sd_udp->flags |= SCM_FLAG_UDPNEW;
	    common_data.scm_send_msg(-1, (struct scm_data *) sd_udp, cur);
	    DebugOut(DEBUG_NET);
	    return;
	}

	// a client stays with the worker that has its context
	struct udp_client *c = udp_client_lookup(&sd_udp->client);
	if (c) {
	    sd_udp->id = c->id;
	    if (udp_send(c->server, sd_udp, listener) < 1) {
		DebugOut(DEBUG_NET);
		return;
	    }
	    logerr("scm_send_msg (%s:%d), pid: %d", __FILE__, __LINE__, (int) c->server->pid);
	    spawnd_cleanup_internal(c->server, c->server->fn);
	}
	// no worker can take a new client now; the client sends again
	if (common_data.users_cur >= common_data.users_max_total) {
	    DebugOut(DEBUG_NET);
	    return;
	}
	sd_udp->flags |= SCM_FLAG_UDPNEW;
	sd_udp->id = ++spawnd_data.udp_client_id;
    } else {
	s = accept(cur, &sa.sa, &sa_len);
	if (s < 0) {
	    if (errno != EAGAIN && errno != EWOULDBLOCK)
		logerr("accept (%s:%d)", __FILE__, __LINE__);
	    DebugOut(DEBUG_NET);
	    return;
	}

	if (common_data.users_cur == common_data.users_max_total) {
	    close(s);
	    DebugOut(DEBUG_NET);
	    return;
	}

	if (!spawnd_acl_check(&sa)) {
	    char buf[INET6_ADDRSTRLEN];
	    close(s);
	    if (errno != EAGAIN && errno != EWOULDBLOCK)
		logerr("connection attempt from [%s] rejected", su_ntoa(&sa, buf, (socklen_t) sizeof(buf)));
	    DebugOut(DEBUG_NET);
	    return;
	}

	flags = fcntl(s, F_GETFD, 0) | FD_CLOEXEC;
	fcntl(s, F_SETFD, flags);

	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));
	switch (sa.sa.sa_family) {
#if defined(AF_INET) && defined(IPPROTO_IP) && defined(IP_TOS)
	case AF_INET:
	    if (ctx->dscp)
		setsockopt(s, IPPROTO_IP, IP_TOS, &ctx->dscp, sizeof(ctx->dscp));
	    break;
#endif
#if defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_TCLASS)
	case AF_INET6:
	    if (ctx->dscp)
		setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &ctx->dscp, sizeof(ctx->dscp));
	    break;
#endif
	default:
	    ;
	}

#ifdef TCP_KEEPCNT		/* __linux__ */
	if ((ctx->keepcnt > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, (char *) &ctx->keepcnt, (socklen_t) sizeof(ctx->keepcnt)) < 0))
	    ctx->keepcnt = -1;
#endif
#ifdef TCP_KEEPIDLE		/* __linux__ */
	if ((ctx->keepidle > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, (char *) &ctx->keepidle, (socklen_t) sizeof(ctx->keepidle)) < 0))
	    ctx->keepidle = -1;
#endif
#ifdef TCP_KEEPINTVL		/* __linux__ */
	if ((ctx->keepintvl > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, (char *) &ctx->keepintvl, (socklen_t) sizeof(ctx->keepintvl)) < 0))
	    ctx->keepintvl = -1;
#endif
#ifdef TCP_KEEPALIVE		/* __APPLE__ */
	if ((ctx->keepidle > -1)
	    && (setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, (char *) &ctx->keepidle, (socklen_t) sizeof(ctx->keepidle)) < 0))
	    ctx->keepidle = -1;
#endif

	sd = alloca(sizeof(struct scm_data_accept));
	sd->type = SCM_ACCEPT;
	sd->flags = ctx->sd_flags;
	sd->tls_versions = ctx->tls_versions;
	sd->aaa_protocol = ctx->aaa_protocol;
	sd->protocol = ctx->protocol;
	memcpy(sd->realm, ctx->tag, SCM_REALM_SIZE);
    }

    /* Server selection algorithm */

    if (!common_data.singleprocess)
	while (common_data.servers_cur < common_data.servers_min)
	    spawnd_add_child();
    su_ptoh(&sa, &addr);

    if (common_data.singleprocess)
	common_data.scm_send_msg(-1, (struct scm_data *) sd, s);
    else {
	struct track_data *track_data = (ctx->track_data.tracking_period > 0) ? &ctx->track_data : &spawnd_data.track_data;
	struct iovec iov[5];
	size_t iov_len = 0;
	// cover source address
	switch (sa.sa.sa_family) {
#ifdef AF_INET
	case AF_INET:
	    iov[iov_len].iov_base = &sa.sin.sin_addr;
	    iov[iov_len++].iov_len = 4;
	    break;
#endif
#ifdef AF_INET6
	case AF_INET6:
	    iov[iov_len].iov_base = &sa.sin6.sin6_addr;
	    iov[iov_len++].iov_len = 16;
	    break;
#endif
	default:
	    ;
	}
	// cover destination port
	iov[iov_len].iov_base = &ctx->port;
	iov[iov_len++].iov_len = sizeof(ctx->port);
	// u is hashed by md5v() below, so it has to outlive the if/else
	u_char u;
	if (sd) {
	    // TCP: cover protocol
	    u = IPPROTO_TCP;
	    iov[iov_len].iov_base = &u;
	    iov[iov_len++].iov_len = 1;
	} else {
	    // UDP: cover protocol and source port
	    u = IPPROTO_UDP;
	    iov[iov_len].iov_base = &u;
	    iov[iov_len++].iov_len = 1;
	    switch (sa.sa.sa_family) {
#ifdef AF_INET
	    case AF_INET:
		iov[iov_len].iov_base = &sa.sin.sin_port;
		iov[iov_len++].iov_len = sizeof(sa.sin.sin_port);
		break;
#endif
#ifdef AF_INET6
	    case AF_INET6:
		iov[iov_len].iov_base = &sa.sin6.sin6_port;
		iov[iov_len++].iov_len = sizeof(sa.sin6.sin6_port);;
		break;
#endif
	    default:
		;
	    }
	}

	u_char digest[MD5_DIGEST_SIZE];
	md5v(digest, sizeof(digest), iov, iov_len);

	min_i = tracking_lookup(track_data, digest);
	do {
	    min = common_data.users_max;
	    // A server told it may die (SCM_MAY_DIE) exits as soon as it is idle,
	    // without reading what is still queued on its socket: a connection
	    // handed to it now would be reset.
	    if (min_i > -1 && (spawnd_data.server_arr[min_i]->use >= common_data.users_max || spawnd_data.server_arr[min_i]->dying))
		min_i = -1;

	    if (min_i < 0)
		for (int i = 0; i < common_data.servers_min && i < common_data.servers_cur; i++)
		    if (!spawnd_data.server_arr[i]->dying && spawnd_data.server_arr[i]->use < common_data.users_min && spawnd_data.server_arr[i]->use < min)
			min_i = i, min = spawnd_data.server_arr[i]->use;

	    if (min_i < 0)
		for (int i = common_data.servers_min; i < common_data.servers_cur; i++)
		    if (!spawnd_data.server_arr[i]->dying && spawnd_data.server_arr[i]->use < common_data.users_min && spawnd_data.server_arr[i]->use < min)
			min_i = i, min = spawnd_data.server_arr[i]->use;

	    // A dying server is idle and exits soon: free its slot now, as it would be a moment later.
	    if (min_i < 0 && common_data.servers_cur == common_data.servers_max)
		for (int i = 0; i < common_data.servers_cur; i++)
		    if (spawnd_data.server_arr[i]->dying) {
			spawnd_cleanup_internal(spawnd_data.server_arr[i], spawnd_data.server_arr[i]->fn);
			break;
		    }

	    if (min_i < 0 && common_data.servers_cur < common_data.servers_max) {
		spawnd_add_child();
		min_i = common_data.servers_cur - 1, min = 0;
	    }

	    if (min_i < 0)
		for (int i = 0; i < common_data.servers_cur; i++)
		    if (spawnd_data.server_arr[i]->use < common_data.users_max && spawnd_data.server_arr[i]->use < min)
			min_i = i, min = spawnd_data.server_arr[i]->use;

	    /* min_i is our selected server. Or -1, which can't happen. */

	    if (min_i == -1) {
		logmsg("BUG (%s:%d)", __FILE__, __LINE__);
		exit(EX_SOFTWARE);
	    }

	    if (sd_udp) {
		res = udp_send(spawnd_data.server_arr[min_i], sd_udp, listener);
		if (res < 0) {	// the client sends again
		    DebugOut(DEBUG_NET);
		    return;
		}
	    } else
		res = common_data.scm_send_msg(spawnd_data.server_arr[min_i]->fn, (struct scm_data *) sd, s);

	    if (res) {
		logerr("scm_send_msg (%s:%d), pid: %d", __FILE__, __LINE__, (int) spawnd_data.server_arr[min_i]->pid);
		spawnd_cleanup_internal(spawnd_data.server_arr[min_i], spawnd_data.server_arr[min_i]->fn);
		if (iteration_cur++ == common_data.servers_max) {
		    /*
		     * This can't possibly happen. We did start additional server
		     * processes in most of the previous iterations.
		     */
		    logmsg("Giving up. Spawned server processes are probably broken." "(%s:%d)", __FILE__, __LINE__);
		    exit(EX_TEMPFAIL);
		}
		min_i = -1;
	    } else {
		if (track_data->tracking_period > 0)
		    tracking_register(track_data, digest, min_i);
		if (sd_udp)
		    udp_client_add(sd_udp, spawnd_data.server_arr[min_i], scm_udp_dtls(sd_udp->data, sd_udp->data_len));
	    }
	}
	while (res);

	if (s > -1)
	    close(s);

	spawnd_data.server_arr[min_i]->use++, common_data.users_cur++;
    }

    if (common_data.users_cur == common_data.users_max_total) {
	logmsg("limit of %d concurrent users reached, %s new connections", common_data.users_cur, spawnd_data.overload_hint);
	set_proctitle(ACCEPT_NO);
	spawnd_data.listeners_inactive = -1;
	// UDP listeners stay: the clients that have a worker keep it, a new client is dropped above
	for (i = 0; i < spawnd_data.listeners_max; i++)
	    if (spawnd_data.listener_arr[i]->socktype != SOCK_DGRAM
		&& spawnd_data.listener_arr[i]->listen_backlog != spawnd_data.listener_arr[i]->overload_backlog)
		listen(spawnd_data.listener_arr[i]->fn, spawnd_data.listener_arr[i]->overload_backlog);
	switch (spawnd_data.overload) {
	case S_queue:
	    for (i = 0; i < spawnd_data.listeners_max; i++)
		if (spawnd_data.listener_arr[i]->socktype != SOCK_DGRAM)
		    io_clr_i(ctx->io, spawnd_data.listener_arr[i]->fn);
	    break;
	case S_reset:
	    for (i = 0; i < spawnd_data.listeners_max; i++)
		if (spawnd_data.listener_arr[i]->socktype != SOCK_DGRAM) {
		    io_close(spawnd_data.listener_arr[i]->io, spawnd_data.listener_arr[i]->fn);
		    spawnd_data.listener_arr[i]->fn = -1;
		}
	    break;
	default:
	    ;
	}

    } else
	set_proctitle(ACCEPT);

    DebugOut(DEBUG_NET);
}
