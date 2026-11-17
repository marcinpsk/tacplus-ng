/*
 * scm.c
 *
 * UNIX domain socket interface for spawnd compliant applications
 * (C)2000-2011 Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#define __SCM_C__
#include "misc/sysconf.h"
#include "misc/memops.h"
#include "log.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "mavis/mavis.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

int scm_send_msg(int sock, struct scm_data *sd, int fd)
{
    struct iovec vector = {.iov_base = sd };
    switch (sd->type) {
    case SCM_ACCEPT:
	vector.iov_len = sizeof(struct scm_data_accept);
	break;
    case SCM_UDPDATA:
	vector.iov_len = sizeof(struct scm_data_udp) + ((struct scm_data_udp *) sd)->data_len;
	break;
    case SCM_UDPDONE:
	vector.iov_len = sizeof(struct scm_data_udpdone);
	break;
    default:
	vector.iov_len = sizeof(struct scm_data);
    }

    struct msghdr msg = {.msg_iov = &vector,.msg_iovlen = 1 };

    char buf[CMSG_SPACE(sizeof(int))] __attribute__((aligned(8))) = { 0 };
    if (fd > -1) {
	msg.msg_control = (caddr_t) buf;
	msg.msg_controllen = sizeof(buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;
    }
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif				/* MSG_NOSIGNAL */

    errno = 0;
    // these never wait for a full queue; the caller sees errno: a datagram is lost, as on the network
    int nowait = sd->type == SCM_UDPDATA || sd->type == SCM_MAY_DIE;
    int res = sendmsg(sock, &msg, MSG_NOSIGNAL | (nowait ? MSG_DONTWAIT : 0));
    if (res < 0 && sd->type != SCM_UDPDATA) {
	int e = errno;
	logmsg("scm_send_msg: sendmsg: %s", strerror(errno));
	errno = e;
    }
    return (res != (ssize_t) vector.iov_len);
}

static int su_cmp_scope(const sockaddr_union *a, const sockaddr_union *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
	return (a->sa.sa_family < b->sa.sa_family) ? -1 : 1;
    int r = 0;
    switch (a->sa.sa_family) {
    case AF_INET:
	r = memcmp(&a->sin.sin_addr, &b->sin.sin_addr, sizeof(a->sin.sin_addr));
	if (!r && a->sin.sin_port != b->sin.sin_port)
	    r = (ntohs(a->sin.sin_port) < ntohs(b->sin.sin_port)) ? -1 : 1;
	break;
    case AF_INET6:
	r = memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, sizeof(a->sin6.sin6_addr));
	if (!r && a->sin6.sin6_port != b->sin6.sin6_port)
	    r = (ntohs(a->sin6.sin6_port) < ntohs(b->sin6.sin6_port)) ? -1 : 1;
	if (!r && a->sin6.sin6_scope_id != b->sin6.sin6_scope_id)
	    r = (a->sin6.sin6_scope_id < b->sin6.sin6_scope_id) ? -1 : 1;
	break;
    }
    return r;
}

int scm_udp_dtls(const u_char *data, size_t len)
{
    // 13: the length of a DTLS record header; 22: handshake; 0xfe: DTLS version
    return len >= 13 && data[0] == 22 && data[1] == 0xfe;
}

int scm_udp_client_cmp(const struct scm_udp_client *a, const struct scm_udp_client *b)
{
    if (a->listener != b->listener)
	return (a->listener < b->listener) ? -1 : 1;
    int r = su_cmp_scope(&a->local, &b->local);
    return r ? r : su_cmp_scope(&a->peer, &b->peer);
}

int scm_recv_msg(int sock, struct scm_data_accept *sd, size_t sd_len, int *fd)
{
    if (fd)
	*fd = -1;

    struct iovec vector = {.iov_base = sd,.iov_len = sd_len };
    char buf[CMSG_SPACE(sizeof(int))] __attribute__((aligned(8)));
    struct cmsghdr *cmsg = (struct cmsghdr *) buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    struct msghdr msg = {.msg_iov = &vector,.msg_iovlen = 1,.msg_controllen = CMSG_SPACE(sizeof(int)),.msg_control = (caddr_t) cmsg };
    size_t len = 0;

    int res = Recvmsg(sock, &msg, MSG_PEEK);
    if (res < 1) {
	logmsg("scm_recv_msg: recvmsg: EoF");
	return -1;
    }

    int fd_peek = -1;
    if (sd->type == SCM_UDPDATA) {
	len = sizeof(struct scm_data_udp) + ((struct scm_data_udp *) sd)->data_len;
	if (len <= sd_len)
	    vector.iov_len = len;
    }
    if (sd->type == SCM_ACCEPT || sd->type == SCM_UDPDATA) {
	// MSG_PEEK apparently accepts the file descriptor. This is unexpected, and implementations may vary.
	struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	if (chdr)
	    memcpy(&fd_peek, CMSG_DATA(chdr), sizeof(int));
    }

    errno = 0;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));
    res = Recvmsg(sock, &msg, 0);

    if (len && len > sd_len) {
	logmsg("scm_recv_msg: recvmsg: buffer too small (%lu < %lu)", sd_len, len);
	return -1;
    }
    if (0 < res) {
	if (sd->type == SCM_ACCEPT || sd->type == SCM_UDPDATA) {
	    struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	    if (chdr)
		memcpy(fd, CMSG_DATA(chdr), sizeof(int));
	    if (*fd > -1 && fd_peek > -1 && *fd != fd_peek) {
		close(fd_peek);
		fd_peek = -1;
	    } else if (*fd < 0)
		*fd = fd_peek;
	}
	return 0;
    }
    if (res < 0)
	logmsg("scm_recv_msg: recvmsg: %s", strerror(errno));
    return -1;
}

int fakescm_send_msg(int sock __attribute__((unused)), struct scm_data *sd, int fd)
{
    switch (sd->type) {
    case SCM_ACCEPT:
	common_data.scm_accept(fd, (struct scm_data_accept *) sd);
	break;
    case SCM_UDPDATA:
	if (common_data.scm_udpdata)
	    common_data.scm_udpdata(fd, (struct scm_data_udp *) sd);
	break;
    case SCM_MAX:
	common_data.users_max = common_data.users_max_total = ((struct scm_data *) sd)->count;
	break;
    default:
	;
    }
    return 0;
}

int fakescm_recv_msg(int sock
		     __attribute__((unused)), struct scm_data_accept *sd
		     __attribute__((unused)), size_t sd_len __attribute__((unused)), int *fd __attribute__((unused)))
{
    return 0;
}

void scm_fatal(void)
{
    struct scm_data sd = {.type = SCM_BAD_CFG };
    common_data.scm_send_msg(0, &sd, -1);
    exit(EX_CONFIG);

}
