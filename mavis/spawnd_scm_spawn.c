/*
 * scm_spawn.c
 *
 * (C)2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 */

#include "misc/sysconf.h"
#include "spawnd_headers.h"
#include <grp.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <sysexits.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

// The server gets no new connection and no new client; its users no longer count.
static void server_remove(struct spawnd_context *ctx)
{
    int i;
    for (i = 0; i < common_data.servers_cur && ctx != spawnd_data.server_arr[i]; i++);
    if (i < common_data.servers_cur) {
	common_data.users_cur -= ctx->use;
	ctx->use = 0;
	spawnd_adjust_tracking(i, -1);
	common_data.servers_cur--;
	spawnd_data.server_arr[i] = spawnd_data.server_arr[common_data.servers_cur];
	spawnd_adjust_tracking(common_data.servers_cur, i);
	spawnd_data.server_arr[common_data.servers_cur] = NULL;
    }
    for (i = 0; i < spawnd_data.retired_cur && ctx != spawnd_data.retired_arr[i]; i++);
    if (i < spawnd_data.retired_cur)
	spawnd_data.retired_arr[i] = spawnd_data.retired_arr[--spawnd_data.retired_cur];
}

void spawnd_cleanup_internal(struct spawnd_context *ctx, int fd __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    io_close(ctx->io, ctx->fn);

    while (io_sched_pop(ctx->io, ctx));

    if (ctx->is_listener)
	spawnd_data.listeners_max--;
    else {
	server_remove(ctx);
	spawnd_udp_forget(ctx);
	set_proctitle(ACCEPT);
    }

    free(ctx);

    DebugOut(DEBUG_PROC);
}

// A server that retires (SCM_DYING) keeps its DTLS clients, as it keeps its TCP connections, until their contexts end.
void spawnd_retire(struct spawnd_context *ctx)
{
    if (ctx->retired)
	return;
    spawnd_udp_forget_plain(ctx);
    if (!ctx->udp_clients) {
	spawnd_cleanup_internal(ctx, ctx->fn);
	return;
    }
    server_remove(ctx);
    ctx->retired = 1;
    spawnd_data.retired_arr = Xrealloc(spawnd_data.retired_arr, (spawnd_data.retired_cur + 1) * sizeof(struct spawnd_context *));
    spawnd_data.retired_arr[spawnd_data.retired_cur++] = ctx;
    set_proctitle(ACCEPT);
}

int spawnd_spawn_child(pid_t * pidp)
{
    int socks[2];
    pid_t pid;
    int flags;
    int bufsize = spawnd_data.scm_bufsize;
    int one = 1;
    char *argv[10];
    int i = 0;
    char *deb = alloca(20);

    memset(&argv, 0, sizeof(argv));

    argv[i++] = spawnd_data.child_path;
    if (common_data.version_only)
	argv[i++] = "-v";
    if (common_data.parse_only)
	argv[i++] = "-P";
    if (common_data.debug) {
	argv[i++] = "-d";
	snprintf(deb, 20, "%u", common_data.debug);
	argv[i++] = deb;
    }
    if (common_data.debugstderr)
	argv[i++] = "-D";
    argv[i++] = spawnd_data.child_config;
    argv[i++] = spawnd_data.child_id;
    argv[i++] = NULL;

    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, socks)) {
	logerr("socketpair (%s:%d)", __FILE__, __LINE__);
	exit(EX_OSERR);
    }
    // room for the largest datagram that spawnd passes: some systems keep less by default
    for (int s = 0; s < 2; s++) {
	int opts[] = { SO_SNDBUF, SO_RCVBUF };
	for (int o = 0; o < 2; o++) {
	    int size = 0, min = (int) (sizeof(struct scm_data_udp) + SCM_UDP_DATA_MAX);
	    socklen_t size_len = (socklen_t) sizeof(size);
	    if (!getsockopt(socks[s], SOL_SOCKET, opts[o], &size, &size_len) && size < min)
		setsockopt(socks[s], SOL_SOCKET, opts[o], &min, (socklen_t) sizeof(min));
	}
    }

    switch ((pid = fork())) {
    case 0:
	// io_destroy(common_data.io, NULL);
	close(socks[0]);
	dup2(socks[1], 0);
	close(socks[1]);
	if (bufsize) {
	    setsockopt(0, SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	    setsockopt(0, SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	}
	setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));

	if (common_data.parse_only)
	    execv(spawnd_data.child_path, argv);
	else {
	    if (spawnd_data.uid)
		setgroups(0, NULL);

	    if (spawnd_data.gid && setgid(spawnd_data.gid))
		logerr("Can't set group id to %d", (int) spawnd_data.gid);

	    if (spawnd_data.uid && setuid(spawnd_data.uid))
		logerr("Can't set user id to %d", (int) spawnd_data.uid);

	    if (spawnd_data.cwd && chdir(spawnd_data.cwd))
		logerr("Can't chdir to %s", spawnd_data.cwd);

	    execv(spawnd_data.child_path, argv);
	}

	logerr("execl (%s, ...) (%s:%d)", spawnd_data.child_path, __FILE__, __LINE__);
	if (!strchr(spawnd_data.child_path, '/'))
	    logmsg("Try calling %s with its absolute path, and this " "problem will go away.", spawnd_data.child_path);
	exit(EX_OSERR);
    case -1:
	logerr("fork (%s:%d)", __FILE__, __LINE__);
	exit(EX_OSERR);
    default:
	close(socks[1]);
	flags = fcntl(socks[0], F_GETFD, 0) | FD_CLOEXEC;
	fcntl(socks[0], F_SETFD, flags);
	if (bufsize) {
	    setsockopt(socks[0], SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	    setsockopt(socks[0], SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, (socklen_t) sizeof(bufsize));
	}
	setsockopt(socks[0], SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));
	if (pidp)
	    *pidp = pid;

	return socks[0];
    }
}

void spawnd_users_done(struct spawnd_context *ctx, int count)
{
    common_data.users_cur -= count, ctx->use -= count;
    if (spawnd_data.listeners_inactive) {
	logmsg("resuming normal operation");
	spawnd_data.listeners_inactive = 0;
	switch (spawnd_data.overload) {
	case S_queue:
	    for (int i = 0; i < spawnd_data.listeners_max; i++) {
		if (spawnd_data.listener_arr[i]->socktype != SOCK_DGRAM
		    && spawnd_data.listener_arr[i]->listen_backlog != spawnd_data.listener_arr[i]->overload_backlog)
		    listen(spawnd_data.listener_arr[i]->fn, spawnd_data.listener_arr[i]->listen_backlog);
		io_set_i(ctx->io, spawnd_data.listener_arr[i]->fn);
	    }
	    break;
	case S_reset:
	    for (int i = 0; i < spawnd_data.listeners_max; i++)
		if (spawnd_data.listener_arr[i]->socktype != SOCK_DGRAM)
		    spawnd_bind_listener(spawnd_data.listener_arr[i], spawnd_data.listener_arr[i]->fn);
	    break;
	default:;
	}
    }
    set_proctitle(ACCEPT);
}

static void recv_childmsg(struct spawnd_context *ctx, int cur)
{
    int max = -1;
    union {
	struct scm_data_accept sd;
	struct scm_data_udpdone udpdone;
    } u;
    int result = common_data.scm_recv_msg(cur, &u.sd, sizeof(u), NULL);

    if (result)
	spawnd_cleanup_internal(ctx, cur);
    else
	switch (u.sd.type) {
	case SCM_DONE:
	    // the users of a retired server no longer count
	    if (!ctx->retired)
		spawnd_users_done(ctx, ((struct scm_data *) &u.sd)->count);
	    break;
	case SCM_UDPDONE:
	    spawnd_udp_done(ctx, &u.udpdone);
	    break;
	case SCM_BAD_CFG:
	    logmsg("Child reported fatal configuration problem. Exiting.");
	    exit(EX_CONFIG);
	case SCM_DYING:
	    spawnd_retire(ctx);
	    break;
	case SCM_MAX:
	    max = (((struct scm_data *) &u.sd))->count;
	    if (common_data.users_max > max) {
		common_data.users_max = max;
		logmsg("child limits maximum number of users to %d", common_data.users_max);
		set_proctitle(ACCEPT);
	    }
	    break;
	case SCM_KEEPALIVE:
	    break;
	default:
	    logmsg("Child used unknown message type %d", (int) u.sd.type);
	}
}

void spawnd_register_server(struct spawnd_context *ctx)
{
    io_register(common_data.io, ctx->fn, ctx);
    io_set_cb_i(common_data.io, ctx->fn, (void *) recv_childmsg);
    io_set_cb_h(common_data.io, ctx->fn, (void *) spawnd_cleanup_internal);
    io_set_cb_e(common_data.io, ctx->fn, (void *) spawnd_cleanup_internal);
    io_set_cb_o(common_data.io, ctx->fn, (void *) spawnd_udp_flush);
    io_set_i(common_data.io, ctx->fn);
}

void spawnd_add_child()
{
    if (common_data.servers_cur < common_data.servers_max) {
	pid_t pid;
	int cur = spawnd_spawn_child(&pid);
	if (cur > -1) {
	    struct spawnd_context *ctx = spawnd_new_context(common_data.io);
	    ctx->pid = pid;
	    ctx->fn = cur;
	    ctx->tv = io_now;
	    spawnd_register_server(ctx);
	    spawnd_data.server_arr[common_data.servers_cur++] = ctx;
	}
    }
}
