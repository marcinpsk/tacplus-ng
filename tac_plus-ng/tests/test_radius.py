# Copyright (C) 2026 TaranacLabs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL ITS AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""RADIUS: Access-Request with PAP over UDP and RADIUS/TCP."""

import contextlib
import errno
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from tactest import (LINUX, SOURCE, DaemonTestCase, Stub, config, features, ipv6_available, local_address, radius,
                     tacacs)
from tactest.daemon import alive, binary, free_udp_port, parse_only, proc_stat, sanitizer_env

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"
CLOSE_TIMEOUT = 10.0    # waiting for the daemon to close a connection: generous, it does come

POLICY = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (aaa.protocol == radius) {
				set radius[Reply-Message] = "welcome"
				permit
			}
			if (service == shell) permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)


def udp_sockets(address, port):
    """The UDP sockets of this host bound to address and port, from /proc/net/udp or udp6 (Linux)."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    n = 0
    with open("/proc/net/udp" + ("6" if family == socket.AF_INET6 else "")) as f:
        for line in f.readlines()[1:]:
            local, local_port = line.split()[1].rsplit(":", 1)
            words = bytes.fromhex(local)     # 32-bit words in host byte order
            raw = b"".join(words[i:i + 4][::-1] if sys.byteorder == "little" else words[i:i + 4]
                           for i in range(0, len(words), 4))
            if int(local_port, 16) == port and socket.inet_ntop(family, raw) == address:
                n += 1
    return n


def resume(pid, starttime):
    """SIGCONT for a stopped worker that may have exited since, and not to a new process of that PID."""
    if not alive(pid, starttime):
        return
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGCONT)


# a second local IPv6 address: tests/loopback-aliases adds it
NAS6 = "fd00:7ac::6"


@unittest.skipUnless(ipv6_available() and local_address(NAS6), "no local address %s (tests/loopback-aliases)" % NAS6)
class PapOverIpv6(DaemonTestCase):
    """The reply to a datagram for [::1] comes from [::1], also for a client with another local source address.

    spawnd binds the reply socket to the destination address of the datagram (IPV6_RECVPKTINFO).
    Without it, the system picks the source address, and the client, connected to [::1], drops the reply.
    """

    CONFIG = POLICY.replace("address = 127.0.0.6", "address = %s" % NAS6)
    ADDRESS = "::1"
    UDP = True

    def test_access_accept(self):
        r = self.radius(SECRET, source=NAS6).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)


@unittest.skipUnless(ipv6_available() and local_address(NAS6), "no local address %s (tests/loopback-aliases)" % NAS6)
class AdoptedUdpListener(DaemonTestCase):
    """spawnd takes over a UDP listener at a SIGHUP, and sets the options that a new listener gets.

    An older image can have made the listener without IPV6_RECVPKTINFO. For a wildcard listener, the
    worker then had no destination address to reply from, and the reply came from another address
    than the client sent to (see PapOverIpv6).
    """

    CONFIG = None

    def test_reply_from_the_address_of_the_listener(self):
        listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)   # as su_bind() made it, no IPV6_RECVPKTINFO
        self.addCleanup(listener.close)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("::", 0))
        port = listener.getsockname()[1]
        self.start_daemon(PapOverIpv6.CONFIG, address="::1", inherit=listener,
                          spawnd="\tlisten { address = :: port = %d protocol = UDP }\n" % port)
        if LINUX:   # spawnd took the socket over and made none of its own
            self.assertEqual(udp_sockets("::", port), 1)
        c = radius.Client(("::1", port), SECRET, source=NAS6, timeout=2.0)
        self.addCleanup(c.close)
        self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")


class UdpListener(DaemonTestCase):
    """spawnd reads every datagram from the one listener socket and passes it to the worker of its client.

    spawnd made a socket for each new client: bind() to the address and port
    of the listener with SO_REUSEADDR, then connect() to the client. A
    datagram of another client that came between the two went to that
    socket. For the same reason the listener had SO_REUSEADDR, so any local
    user could bind its port and get its datagrams.
    """

    CONFIG = None
    CLIENTS = 200

    def test_many_clients_at_once(self):
        """Every client sends its request before any reply is read; each gets its own Access-Accept."""
        d = self.start_daemon(POLICY, udp=True, spawnd="\tspawn { users max = %d }\n" % (2 * self.CLIENTS))
        clients = [self.radius(SECRET, daemon=d, source=NAS) for _ in range(self.CLIENTS)]
        requests = [c.pap_request("alice", "alicepw") for c in clients]
        for c, req in zip(clients, requests):
            c.send_raw(req.encode(c.secret, message_authenticator=True))
        deadline = time.monotonic() + 10.0
        failed = []
        for c, req in zip(clients, requests):
            c.sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                r = c.reply(req)
                if r.code_name != "Access-Accept":
                    failed.append(r.code_name)
            except (TimeoutError, radius.ProtocolError) as e:
                failed.append(type(e).__name__)
        self.assertEqual(failed, [], "%d of %d clients got no Access-Accept" % (len(failed), self.CLIENTS))

    def test_port_cannot_be_bound_again(self):
        """No SO_REUSEADDR or SO_REUSEPORT on the listener: another socket on its address and port must fail."""
        d = self.start_daemon(POLICY, udp=True)
        options = [[socket.SO_REUSEADDR]]
        if hasattr(socket, "SO_REUSEPORT"):
            options += [[socket.SO_REUSEPORT], [socket.SO_REUSEADDR, socket.SO_REUSEPORT]]
        for opts in options:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for opt in opts:
                    s.setsockopt(socket.SOL_SOCKET, opt, 1)
                with self.assertRaises(OSError, msg="bind with options %s succeeded" % opts) as e:
                    s.bind(d.udp_addr)
                self.assertEqual(e.exception.errno, errno.EADDRINUSE)
        r = self.radius(SECRET, daemon=d, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_port_of_an_adopted_listener_cannot_be_bound_again(self):
        """A listener taken over at a SIGHUP loses SO_REUSEADDR and SO_REUSEPORT: a new one has neither.

        An older image set SO_REUSEADDR (su_bind()), and on the BSDs SO_REUSEPORT too.
        """
        options = [[socket.SO_REUSEADDR]]
        if hasattr(socket, "SO_REUSEPORT"):
            options += [[socket.SO_REUSEPORT], [socket.SO_REUSEADDR, socket.SO_REUSEPORT]]
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(listener.close)
        for opt in options[-1]:
            listener.setsockopt(socket.SOL_SOCKET, opt, 1)
        listener.bind(("127.0.0.1", 0))
        d = self.start_daemon(POLICY, udp=True, inherit=listener)
        for opts in options:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for opt in opts:
                    s.setsockopt(socket.SOL_SOCKET, opt, 1)
                with self.assertRaises(OSError, msg="bind with options %s succeeded" % opts) as e:
                    s.bind(d.udp_addr)
                self.assertEqual(e.exception.errno, errno.EADDRINUSE)
        r = self.radius(SECRET, daemon=d, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    @unittest.skipUnless(LINUX, "SO_REUSEPORT of Linux; FreeBSD uses SO_REUSEPORT_LB, OpenBSD has no reuse-port")
    def test_adopted_listener_gets_reuse_port_when_configured(self):
        """A listener without SO_REUSEPORT, taken over with "reuse-port = yes" (a reload from "no" to "yes"), gets it."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        self.start_daemon(POLICY, udp=True, inherit=listener, spawnd="\treuse-port = yes\n")
        self.assertEqual(listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT), 1)

    @unittest.skipUnless(LINUX, "SO_REUSEPORT of Linux; FreeBSD uses SO_REUSEPORT_LB, OpenBSD has no reuse-port")
    def test_adopted_listener_keeps_reuse_port_when_configured(self):
        """With "reuse-port = yes", a listener taken over at a SIGHUP has SO_REUSEPORT, as a new one has."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(listener.close)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        listener.bind(("127.0.0.1", 0))
        d = self.start_daemon(POLICY, udp=True, inherit=listener, spawnd="\treuse-port = yes\n")
        self.assertEqual(listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT), 1)
        r = self.radius(SECRET, daemon=d, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_many_clients_at_once_with_two_workers(self):
        """Each client stays with the worker that has its context; both workers get clients."""
        d = self.start_daemon(POLICY, udp=True,
                              spawnd="\tspawn { instances min = 2 instances max = 2 users max = %d }\n" % self.CLIENTS)
        self.assertEqual(len(d.workers()), 2)
        clients = [self.radius(SECRET, daemon=d, source=NAS) for _ in range(self.CLIENTS)]
        for _ in range(2):
            requests = [c.pap_request("alice", "alicepw") for c in clients]
            for c, req in zip(clients, requests):
                c.send_raw(req.encode(c.secret, message_authenticator=True))
            failed = []
            for c, req in zip(clients, requests):
                try:
                    if c.reply(req).code_name != "Access-Accept":
                        failed.append(c)
                except (TimeoutError, radius.ProtocolError):
                    failed.append(c)
            self.assertEqual(len(failed), 0, "%d of %d clients got no Access-Accept" % (len(failed), self.CLIENTS))
        users = sorted(d.users(pid) for pid in d.workers())
        self.assertEqual(sum(users), self.CLIENTS, "contexts of the workers")
        self.assertGreater(users[0], 0, "one worker got no client")

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_client_moves_when_its_worker_is_gone(self):
        """spawnd forgets the clients of a worker that went away; their next datagram goes to another worker."""
        d = self.start_daemon(POLICY, udp=True)
        c = self.radius(SECRET, daemon=d, source=NAS)
        self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")
        (worker,) = d.workers()
        d.baseline.forget(worker)
        os.kill(worker, signal.SIGKILL)
        deadline = time.monotonic() + 5.0
        while alive(worker) and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")
        self.assertNotIn(worker, d.workers())

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_a_stopped_worker_does_not_stop_spawnd(self):
        """spawnd does not wait for a worker to take a datagram: the datagram waits in spawnd, beyond a limit it is lost.

        A worker that reads nothing fills its queue with the datagrams of its client. spawnd waited in
        sendmsg() then, and took no TCP connection and no datagram for any other worker.
        """
        d = self.start_daemon(POLICY, udp=True, spawnd="\tspawn { instances min = 2 instances max = 2 }\n")
        c = self.radius(SECRET, daemon=d, source=NAS)
        self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")
        (stopped,) = [pid for pid in d.workers() if d.users(pid) == 1]
        os.kill(stopped, signal.SIGSTOP)
        self.addCleanup(os.kill, stopped, signal.SIGCONT)
        deadline = time.monotonic() + 5.0
        while proc_stat(stopped)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        for _ in range(3000):
            c.send_raw(b"x" * 100)
        with d.connect(timeout=5.0) as t:
            self.assertTrue(t.pap("alice", "alicepw").ok)
        # until spawnd counts the end of the TCP connection, both workers have one user, and the new client can go
        # to the stopped one
        deadline = time.monotonic() + 5.0
        while d.users() != 1 and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        r = self.radius(SECRET, daemon=d, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_burst_while_the_worker_is_busy(self):
        """Datagrams that come while the worker reads none wait in spawnd, up to a limit, and are not lost.

        The socket to a worker holds about 200 datagrams (Linux). When it was full, spawnd dropped
        the next datagram at once, so a burst of new clients lost requests.
        """
        clients = 500
        d = self.start_daemon(POLICY, udp=True, spawnd="\tspawn { users max = %d }\n" % (2 * clients))
        (worker,) = d.workers()
        os.kill(worker, signal.SIGSTOP)
        self.addCleanup(os.kill, worker, signal.SIGCONT)
        deadline = time.monotonic() + 5.0
        while proc_stat(worker)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        burst = [self.radius(SECRET, daemon=d, source=NAS) for _ in range(clients)]
        requests = [c.pap_request("alice", "alicepw") for c in burst]
        for i, (c, req) in enumerate(zip(burst, requests)):
            c.send_raw(req.encode(c.secret, message_authenticator=True))
            if i % 50 == 49:    # the listener holds about 200 datagrams too: let spawnd read them into its queue
                deadline = time.monotonic() + 5.0
                while d.udp_queued() and time.monotonic() < deadline:
                    select.select([], [], [], 0.01)
        os.kill(worker, signal.SIGCONT)
        deadline = time.monotonic() + 20.0
        failed = 0
        for c, req in zip(burst, requests):
            c.sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                if c.reply(req).code_name != "Access-Accept":
                    failed += 1
            except (TimeoutError, radius.ProtocolError):
                failed += 1
        self.assertEqual(failed, 0, "%d of %d clients got no Access-Accept" % (failed, clients))

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_sighup_with_a_stopped_worker(self):
        """SIGHUP sends SCM_MAY_DIE without waiting for room in the socket of a worker.

        spawnd waited in sendmsg() for a stopped worker whose socket was full of datagrams, and the
        reload did not happen until the worker went on. That worker does not get SCM_MAY_DIE: it
        keeps its copy of the dropped wildcard listener until its keepalive fails, and the new
        listener on the same port must bind after that, also when this is later than the 5 s of
        fast bind retries, and also after a second reload while the bind still waits.
        """
        port = free_udp_port("0.0.0.0")
        spawn = "\tspawn { instances min = 2 instances max = 2 }\n"
        # two workers: a TCP connection still waits for a full socket, so the probe of reload() goes to the other one
        d = self.start_daemon(POLICY, spawnd=spawn + "\tlisten { address = 0.0.0.0 port = %d protocol = UDP }\n" % port)
        c = radius.Client(("127.0.0.1", port), SECRET, source=NAS)
        self.addCleanup(c.close)
        self.assertEqual(self.welcome(c), [b"welcome"])
        (worker,) = [pid for pid in d.workers() if d.users(pid) == 1]
        for pid in d.workers():
            d.baseline.forget(pid)  # they exit after the reload
        os.kill(worker, signal.SIGSTOP)
        self.addCleanup(resume, worker, proc_stat(worker)[2])  # it exits when it goes on
        deadline = time.monotonic() + 5.0
        while proc_stat(worker)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        for _ in range(3000):
            c.send_raw(b"x" * 100)
        d.spawnd = spawn + "\tlisten { address = 127.0.0.1 port = %d protocol = UDP }\n" % port
        d.reload(POLICY.replace('"welcome"', '"welcome back"'))
        d.reload(POLICY.replace('"welcome"', '"welcome again"'))  # the listener of the first reload is not bound yet
        time.sleep(6)  # the new image tried the first bind before the reload was visible
        os.kill(worker, signal.SIGCONT)
        with radius.Client(("127.0.0.1", port), SECRET, source=NAS) as c:
            r = c.retransmit(c.pap_request("alice", "alicepw"), message_authenticator=True, tries=8)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"welcome again"], r)

    def welcome(self, c):
        r = c.access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return r.get(radius.REPLY_MESSAGE)

    def test_plain_client_gets_the_new_policy_after_sighup(self):
        """Plain RADIUS/UDP has no session: after SIGHUP the next request of a client goes to a new worker at once.

        A client that kept sending kept its context in the old worker, with the old policy, without
        a limit: a user that the reload removed stayed accepted. The reload changes the reply
        message and removes bob, so the replies tell the workers apart.
        """
        policy = POLICY.replace("\tuser alice {", "\tuser bob {\n\t\tpassword login = clear bobpw\n\t\tpassword pap = login\n\t}\n\tuser alice {")
        d = self.start_daemon(policy, udp=True)
        c = self.radius(SECRET, daemon=d, source=NAS)
        self.assertEqual(self.welcome(c), [b"welcome"])
        self.assertEqual(c.access_request("bob", "bobpw", message_authenticator=True).code_name, "Access-Accept")
        d.reload(POLICY.replace('"welcome"', '"welcome back"'))
        self.assertEqual(self.welcome(c), [b"welcome back"], "the client stayed with the old worker")
        self.assertEqual(c.access_request("bob", "bobpw", message_authenticator=True).code_name, "Access-Reject")

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_plain_client_leaves_a_retired_worker(self):
        """A worker that retires keeps no plain UDP client: the client goes on with another worker, and the old one exits."""
        d = self.start_daemon("\tretire limit = 1\n" + POLICY, udp=True)
        (old,) = d.workers()
        d.baseline.forget(old)
        c = self.radius(SECRET, daemon=d, source=NAS)
        deadline = time.monotonic() + 10.0
        while alive(old) and time.monotonic() < deadline:
            self.assertEqual(self.welcome(c), [b"welcome"])
            select.select([], [], [], 0.2)
        self.assertFalse(alive(old), "the retired worker still serves the client")
        self.assertEqual(self.welcome(c), [b"welcome"])

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_retired_worker_gives_back_the_user_limit(self):
        """UDP clients that reach the user limit pause the TCP listener; the users that a retiring worker frees resume it."""
        d = self.start_daemon("\tretire limit = 2\n" + POLICY, udp=True,
                              spawnd="\tspawn { instances min = 1 instances max = 1 users max = 2 }\n")
        (old,) = d.workers()
        d.baseline.forget(old)
        for _ in range(2):  # the second context makes the worker retire, at the limit of 2 users
            r = self.radius(SECRET, daemon=d, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
            self.assertEqual(r.code_name, "Access-Accept", r)
        with d.connect(timeout=5.0) as t:
            self.assertTrue(t.pap("alice", "alicepw").ok)

    def test_sighup_replaces_a_wildcard_listener(self):
        """A new listener can bind the port of a UDP listener that the reload dropped.

        The old worker kept its copy of the old listener while it lived, here for a TCP
        connection, so the port stayed bound, and the listener of the reload failed to bind.
        """
        port = free_udp_port("0.0.0.0")
        d = self.start_daemon(POLICY, spawnd="\tlisten { address = 0.0.0.0 port = %d protocol = UDP }\n" % port)
        with radius.Client(("127.0.0.1", port), SECRET, source=NAS) as c:
            self.assertEqual(self.welcome(c), [b"welcome"])
        tcp = self.connect(daemon=d)
        d.spawnd = "\tlisten { address = 127.0.0.1 port = %d protocol = UDP }\n" % port
        d.reload()
        # spawnd binds again while the old worker closes its copy; the client sends again, as a RADIUS client does
        deadline, reply = time.monotonic() + 10.0, None
        while reply is None and time.monotonic() < deadline:
            with radius.Client(("127.0.0.1", port), SECRET, source=NAS, timeout=0.5) as c:
                try:
                    reply = self.welcome(c)
                except (TimeoutError, ConnectionRefusedError):
                    pass
        self.assertEqual(reply, [b"welcome"], "no listener on the port after the reload")
        self.assertFalse(tcp.closed(timeout=0.1))

    def wildcard(self, any_address, address, source, policy=POLICY):
        """Access-Request from source to address on a listener of any_address: the client takes only a reply from address."""
        port = free_udp_port(any_address)
        self.start_daemon(policy, spawnd="\tlisten { address = %s port = %d protocol = UDP }\n" % (any_address, port))
        with radius.Client((address, port), SECRET, source=source) as c:
            r = c.access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_wildcard_listener(self):
        """The worker names the source address of the reply (IP_PKTINFO, IP_SENDSRCADDR); else the system picks one.

        Linux picks 127.0.0.1 for a reply to 127.0.0.6, so the request goes to 127.0.0.2.
        """
        self.wildcard("0.0.0.0", "127.0.0.2", NAS)

    @unittest.skipUnless(ipv6_available() and local_address(NAS6), "no local address %s (tests/loopback-aliases)" % NAS6)
    def test_wildcard_listener_ipv6(self):
        self.wildcard("::", "::1", NAS6, POLICY.replace("address = 127.0.0.6", "address = %s" % NAS6))

    @unittest.skipUnless(LINUX and ipv6_available(), "IPv4 on an IPv6 socket")
    def test_wildcard_ipv6_listener_with_ipv4(self):
        self.wildcard("::", "127.0.0.2", NAS)

    def test_wildcard_listener_one_client_two_addresses(self):
        """One client port sends to two addresses of a wildcard listener: two clients, each reply from its address.

        spawnd and the worker named a client by listener and peer only, so the second address got the
        context of the first, and its reply came from the first address.
        """
        port = free_udp_port("0.0.0.0")
        self.start_daemon(POLICY, spawnd="\tlisten { address = 0.0.0.0 port = %d protocol = UDP }\n" % port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((NAS, 0))
            s.settimeout(5.0)
            for address in ("127.0.0.2", "127.0.0.3", "127.0.0.2", "127.0.0.3"):
                req = radius.Packet(radius.ACCESS_REQUEST)
                req.attributes = [(radius.USER_NAME, b"alice"),
                                  (radius.USER_PASSWORD, radius.encrypt_password("alicepw", SECRET, req.authenticator))]
                s.sendto(req.encode(SECRET, message_authenticator=True), (address, port))
                data, source = s.recvfrom(65535)
                self.assertEqual(source, (address, port), "the reply to %s" % address)
                r = radius.Packet.decode(data)
                self.assertEqual((r.code_name, r.identifier), ("Access-Accept", req.identifier))


@unittest.skipUnless(LINUX, "the user count of spawnd from its process title")
class UdpUsers(DaemonTestCase):
    """spawnd counts a UDP client as one user while the worker has its context.

    The worker tells spawnd when a context ends, and when it drops a
    datagram of a client it has no context for. A dropped datagram must not
    use up "users max", and must not end the least recently used context.
    """

    CONFIG = None

    def wait_read(self, d, port=None):
        """Wait until spawnd has read the datagrams on port (by default udp_port): it handled each one when it read it."""
        deadline = time.monotonic() + 5.0
        while d.udp_queued(port) and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(d.udp_queued(port), 0, "spawnd did not read the datagrams")

    def wait_users(self, d, n, datagrams_sent=False):
        """datagrams_sent: first wait until spawnd has read those on udp_port, so that the count is not the one before them."""
        if datagrams_sent:
            self.wait_read(d)
        deadline = time.monotonic() + 5.0
        while d.users() != n and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(d.users(), n, "users of spawnd")

    def bad(self, d):
        """From a new source port, a datagram whose RADIUS length field is not its size."""
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
        self.radius(SECRET, daemon=d, source=NAS).send_raw(req.encode(length=200))

    def test_requests_of_one_client_are_one_user(self):
        d = self.start_daemon(POLICY, udp=True)
        c = self.radius(SECRET, daemon=d, source=NAS)
        for _ in range(5):
            self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")
        self.wait_users(d, 1)

    def test_bad_datagrams_do_not_use_up_the_user_limit(self):
        d = self.start_daemon(POLICY, udp=True, spawnd="\tspawn { users max = 4 }\n")
        for _ in range(6):
            self.bad(d)
        self.wait_users(d, 0, datagrams_sent=True)
        # at the limit spawnd drops the datagram of a new client: the client sends it again, as a RADIUS client does
        c = self.radius(SECRET, daemon=d, source=NAS)
        r = c.retransmit(c.pap_request("alice", "alicepw"), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_lost_queued_datagram_keeps_the_listener_and_the_count(self):
        """A queued datagram that does not fit the socket to the worker is lost, and with it nothing else.

        It took the descriptor of its listener, the first one of listener b for this worker, and
        spawnd took that as passed: the worker never got the listener, and dropped every later
        datagram of b. And spawnd kept the new client of the lost datagram as a user.
        """
        d = self.start_daemon(POLICY, udp=True, listen={"b": "protocol = UDP"}, spawnd="\ttcp bufsize = 4096\n")
        a = self.radius(SECRET, daemon=d, source=NAS)
        self.assertEqual(a.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")
        (worker,) = d.workers()
        os.kill(worker, signal.SIGSTOP)
        self.addCleanup(os.kill, worker, signal.SIGCONT)
        deadline = time.monotonic() + 5.0
        while proc_stat(worker)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        for _ in range(50):
            a.send_raw(b"x" * 100)  # the socket to the worker is full: these wait in spawnd
        # the datagram of b must find the queue, not try the socket first: it does not fit, and is lost at once
        self.wait_read(d)
        self.radius(SECRET, daemon=d, listener="b", source=NAS).send_raw(b"x" * 12000)
        self.wait_read(d, d.ports["b"])
        self.wait_users(d, 2)
        os.kill(worker, signal.SIGCONT)
        self.wait_users(d, 1)
        b = self.radius(SECRET, daemon=d, listener="b", source=NAS)
        r = b.retransmit(b.pap_request("alice", "alicepw"), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    @unittest.skipUnless(LINUX, "workers through /proc")
    def test_lost_queued_datagram_of_a_retired_worker(self):
        """A queued first datagram of a DTLS client is lost after its worker retired: spawnd frees the worker once.

        The client was the last one of the retired worker, so its end freed the worker, and the
        flush of the queue went on with it (use after free; the address sanitizer shows it).
        """
        d = self.start_daemon("\tretire limit = 2\n" + POLICY, udp=True, spawnd="\ttcp bufsize = 4096\n")
        a = self.radius(SECRET, daemon=d, source=NAS)
        self.assertEqual(a.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")
        (worker,) = d.workers()
        d.baseline.forget(worker)  # it retires and exits
        os.kill(worker, signal.SIGSTOP)
        self.addCleanup(resume, worker, proc_stat(worker)[2])
        deadline = time.monotonic() + 5.0
        while proc_stat(worker)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        b = self.radius(SECRET, daemon=d, source=NAS)
        b.send_raw(b.pap_request("alice", "alicepw").encode(b.secret, message_authenticator=True))  # the second context: it retires
        for _ in range(200):
            a.send_raw(b"x" * 100)
        # the first datagram of a new client, a DTLS record: it stays with the retired worker, and does not fit its socket
        self.radius(SECRET, daemon=d, source=NAS).send_raw(bytes([22, 0xfe, 0xfd]) + b"x" * 12000)
        self.wait_users(d, 3, datagrams_sent=True)
        os.kill(worker, signal.SIGCONT)
        deadline = time.monotonic() + 10.0
        while alive(worker) and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertFalse(alive(worker), "the retired worker did not exit")
        c = self.radius(SECRET, daemon=d, source=NAS)
        self.assertEqual(c.retransmit(c.pap_request("alice", "alicepw"), message_authenticator=True).code_name, "Access-Accept")

    @unittest.skipUnless(LINUX, "processes through /proc")
    def test_done_messages_wait_for_spawnd(self):
        """A message of the worker to spawnd (SCM_DONE, SCM_UDPDONE) waits when the socket is full, and is not lost.

        The socket of the worker does not block. A message that did not fit was lost, and spawnd
        counted its user (or kept its UDP client) for ever. Here 1000 connections end while
        spawnd is stopped.
        """
        d = self.start_daemon(POLICY, spawnd="\tspawn { users max = 2000 }\n")
        (worker,) = d.workers()
        conns = []
        for _ in range(1000):
            conns.append(socket.create_connection(d.addr))
            self.addCleanup(conns[-1].close)
        deadline = time.monotonic() + 10.0
        while d.users(worker) < 1000 and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(d.users(worker), 1000)
        os.kill(d.pid, signal.SIGSTOP)
        self.addCleanup(os.kill, d.pid, signal.SIGCONT)
        for c in conns:
            c.close()
        while d.users(worker) and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(d.users(worker), 0)
        os.kill(d.pid, signal.SIGCONT)
        self.wait_users(d, 0)

    def assertLruConnectionKept(self, body, datagram):
        """At "last-recently-used limit", users_inc() ends the oldest context to make room."""
        d = self.start_daemon(body + "\tlast-recently-used limit = 1\n", udp=True)
        c = self.connect(daemon=d)
        self.wait_users(d, 1)  # spawnd passed the connection: the worker reads it before the datagram
        self.radius(SECRET, daemon=d, source=NAS).send_raw(datagram)
        self.wait_users(d, 1, datagrams_sent=True)
        self.assertFalse(c.closed(timeout=1.0), "a dropped datagram ended the TACACS+ connection")
        return c

    def test_bad_datagram_keeps_the_least_recently_used_connection(self):
        c = self.assertLruConnectionKept(POLICY, radius.Packet(radius.ACCESS_REQUEST).encode(length=200))
        self.assertTrue(c.pap("alice", "alicepw").ok)

    def test_datagram_without_a_dictionary_keeps_the_least_recently_used_connection(self):
        self.assertLruConnectionKept("", radius.Packet(radius.ACCESS_REQUEST).encode())


@unittest.skipUnless(LINUX, "process state through /proc")
class Resume(unittest.TestCase):
    def test_no_sigcont_for_another_start_time(self):
        """resume() sends SIGCONT only to the process that had the PID at the start time it got."""
        p = subprocess.Popen(["sleep", "30"])
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        os.kill(p.pid, signal.SIGSTOP)
        deadline = time.monotonic() + 5.0
        while proc_stat(p.pid)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        resume(p.pid, proc_stat(p.pid)[2] + 1)
        select.select([], [], [], 0.2)
        self.assertEqual(proc_stat(p.pid)[0], "T", "SIGCONT for another start time")
        resume(p.pid, proc_stat(p.pid)[2])
        deadline = time.monotonic() + 5.0
        while proc_stat(p.pid)[0] == "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        self.assertNotEqual(proc_stat(p.pid)[0], "T")


class Retransmit(unittest.TestCase):
    """radius.Client.retransmit(): an ICMP port unreachable of an earlier datagram uses up a try, as no reply does."""

    def test_refused_send(self):
        port = free_udp_port("127.0.0.1")    # nothing listens there
        with radius.Client(("127.0.0.1", port), SECRET, source=NAS) as c:     # not 127.0.0.1: no connection to itself
            c.send_raw(b"x")                 # its ICMP error comes with the next send (Linux) or receive
            select.select([], [], [], 0.1)
            with self.assertRaises(TimeoutError):
                c.retransmit(c.pap_request("alice", "alicepw"), tries=2, interval=0.2)


class Pap(DaemonTestCase):
    CONFIG = POLICY
    UDP = True

    def radius(self, secret, **kw):
        kw.setdefault("source", NAS)
        return super().radius(secret, **kw)

    def test_access_accept(self):
        r = self.radius(SECRET).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"welcome"])

    def test_access_reject(self):
        r = self.radius(SECRET).access_request("alice", "wrong", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)

    def test_message_authenticator_accepted(self):
        r = self.radius(SECRET).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_wrong_secret_gets_no_accept(self):
        """The User-Password decodes to garbage: a reject or no answer, never an accept.

        The reply is read without the check of the Response Authenticator,
        which a reply under the daemon's secret could not pass anyway. The
        Message-Authenticator is computed with the daemon's secret, so that
        the request gets past it to the password check.
        """
        c = self.radius(SECRET, timeout=2.0)
        req = radius.Packet(radius.ACCESS_REQUEST)
        password = radius.encrypt_password("alicepw", "not-the-secret", req.authenticator)
        req.attributes = [(radius.USER_NAME, b"alice"), (radius.USER_PASSWORD, password)]
        c.send_raw(req.encode(SECRET, message_authenticator=True))
        try:
            r = radius.Packet.decode(c.recv_raw())
        except TimeoutError:
            return
        self.assertNotEqual(r.code_name, "Access-Accept", r)

    def test_password_that_is_not_utf8(self):
        """#247 was first blamed on a password that doesn't decode as UTF-8: it is just a wrong password."""
        for password in (b"\xff\xfe\xfd", b"caf\xe9", bytes(range(1, 40))):
            with self.subTest(password=password):
                r = self.radius(SECRET).access_request("alice", password, message_authenticator=True)
                self.assertEqual(r.code_name, "Access-Reject", r)

    def test_radius_over_tcp(self):
        """RADIUS/TCP (RFC 6613) on the TACACS+ port: the daemon recognizes the protocol."""
        r = self.radius(SECRET, tcp=True).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_radius_over_tcp_length_below_the_header(self):
        """f02d3bc: a RADIUS/TCP length field below 20 made the data length negative, read as unsigned.

        The daemon allocated about 4 GB for the packet and waited for the
        rest of it. It must drop the connection instead.
        """
        for length in (0, 4, 19):
            with self.subTest(length=length):
                c = self.radius(SECRET, tcp=True, timeout=CLOSE_TIMEOUT)
                req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
                c.send_raw(req.encode(SECRET, message_authenticator=True, length=length))
                with self.assertRaises(ConnectionError):
                    c.recv_raw()


class ReplyAttributes(DaemonTestCase):
    """A Reply-Message is appended after the profile attributes, not written over them.

    A profile that sets an attribute and then denies makes
    rad_send_authen_reply() send an Access-Reject with the profile attribute
    and the "Denied by ACL" Reply-Message. The Reply-Message used to start at
    offset 0 of the attribute buffer, overwriting the first profile attribute
    and leaving a malformed attribute list. Both attributes must be sent.
    """

    CONFIG = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (aaa.protocol == radius) {
				set radius[Framed-IP-Address] = 192.0.2.1
				deny
			}
			if (service == shell) permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)
    UDP = True

    def radius(self, secret, **kw):
        kw.setdefault("source", NAS)
        return super().radius(secret, **kw)

    def test_reply_message_follows_profile_attributes(self):
        r = self.radius(SECRET).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)
        self.assertEqual(r.get(radius.FRAMED_IP_ADDRESS), [socket.inet_aton("192.0.2.1")])
        messages = r.get(radius.REPLY_MESSAGE)
        self.assertEqual(len(messages), 1, r)
        self.assertTrue(messages[0], r)
        if "openssl" in features():
            self.assertIs(r.message_authenticator, True, "Message-Authenticator missing or wrong")


@unittest.skipUnless("openssl" in features(), "the Message-Authenticator needs a build with OpenSSL")
class MessageAuthenticator(DaemonTestCase):
    """Message-Authenticator (RFC 3579 3.2): checked in requests, always set in replies."""

    CONFIG = POLICY
    UDP = True

    def radius(self, secret, **kw):
        kw.setdefault("source", NAS)
        return super().radius(secret, **kw)

    def request(self):
        req = radius.Packet(radius.ACCESS_REQUEST)
        req.attributes = [(radius.USER_NAME, b"alice"),
                          (radius.USER_PASSWORD, radius.encrypt_password("alicepw", SECRET, req.authenticator))]
        return req

    def test_wrong_message_authenticator_gets_no_answer(self):
        """RFC 3579 3.2: a request with a wrong Message-Authenticator is silently discarded."""
        c = self.radius(SECRET, timeout=2.0)
        c.send_raw(self.request().encode(SECRET, message_authenticator=bytes(range(16))))
        with self.assertRaises(TimeoutError):
            c.recv_raw()
        # the same request with the right one is answered
        r = self.radius(SECRET).exchange(self.request(), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept")

    def test_issue200_reply_has_a_message_authenticator(self):
        """#200: clients with "Require Message-Authenticator" need it in the reply (RFC 3579 3.2, BLAST)."""
        for password, code in (("alicepw", "Access-Accept"), ("wrong", "Access-Reject")):
            with self.subTest(reply=code):
                r = self.radius(SECRET).access_request("alice", password, message_authenticator=True)
                self.assertEqual(r.code_name, code, r)
                self.assertIs(r.message_authenticator, True, "Message-Authenticator missing or wrong")

    def test_radius_over_tcp_wrong_message_authenticator_closes(self):
        c = self.radius(SECRET, tcp=True, timeout=CLOSE_TIMEOUT)
        c.send_raw(self.request().encode(SECRET, message_authenticator=bytes(16)))
        with self.assertRaises(ConnectionError):
            c.recv_raw()

    def test_issue200_reply_over_tcp_has_a_message_authenticator(self):
        r = self.radius(SECRET, tcp=True).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertIs(r.message_authenticator, True)


@unittest.skipUnless("openssl" in features(), "the Message-Authenticator needs a build with OpenSSL")
class MessageAuthenticatorRequired(DaemonTestCase):
    """#281 (3): an Access-Request without Message-Authenticator is dropped, unless bug compatibility 32.

    BLAST mitigation as documented for bug compatibility bit 5 (32). The
    check in rad_check_failed() listed only reply codes (Access-Accept,
    -Reject, -Challenge), which the daemon never receives, so every
    request was answered. Over TLS/DTLS the attribute stays optional (see
    test_tls.RadiusOverTls).
    """

    CONFIG = """
	include = "%s"
	device strict {
		address = 127.0.0.6
		radius.key = %s
	}
	device lenient {
		address = 127.0.0.7
		radius.key = %s
		bug compatibility = 32
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	ruleset {
		rule { script { permit } }
	}
""" % (DICTIONARY, SECRET, SECRET)
    UDP = True

    def test_issue281_access_request_without_it_is_dropped(self):
        c = self.radius(SECRET, source="127.0.0.6", timeout=2.0)
        with self.assertRaises(TimeoutError, msg="answered an Access-Request without Message-Authenticator"):
            c.access_request("alice", "alicepw")

    def test_issue281_access_request_without_it_over_tcp_closes(self):
        c = self.radius(SECRET, tcp=True, source="127.0.0.6", timeout=CLOSE_TIMEOUT)
        with self.assertRaises(ConnectionError):
            c.access_request("alice", "alicepw")

    def test_issue281_access_request_with_it(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp):
                r = self.radius(SECRET, tcp=tcp, source="127.0.0.6").access_request("alice", "alicepw",
                                                                                    message_authenticator=True)
                self.assertEqual(r.code_name, "Access-Accept", r)

    def test_issue281_bug_compatibility_32_accepts_it_without(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp):
                r = self.radius(SECRET, tcp=tcp, source="127.0.0.7").access_request("alice", "alicepw")
                self.assertEqual(r.code_name, "Access-Accept", r)

    def test_issue281_accounting_request_needs_none(self):
        """RFC 2866 has no Message-Authenticator in accounting; not required there."""
        c = self.radius(SECRET, source="127.0.0.6")
        r = c.accounting_request([(radius.USER_NAME, b"alice"), (radius.ACCT_STATUS_TYPE, struct.pack("!I", 1))])
        self.assertEqual(r.code_name, "Accounting-Response", r)


class DroppedDatagram(DaemonTestCase):
    """The worker drops a UDP datagram that is not RADIUS; it must close the socket that spawnd passed with it.

    spawnd passes each new source address and port with a socket connected
    to it. A socket the worker kept open after a drop got the later
    datagrams of that source, and nobody read them.
    """

    CONFIG = POLICY
    UDP = True

    def bad(self, client):
        """A datagram whose RADIUS length field is not its size."""
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
        client.send_raw(req.encode(length=200))

    def fds(self, daemon=None):
        (worker,) = (daemon or self.daemon).workers()
        return len(os.listdir("/proc/%d/fd" % worker))

    def assertFdsBack(self, before, daemon=None):
        deadline = time.monotonic() + 5.0
        while self.fds(daemon) > before and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertLessEqual(self.fds(daemon), before, "the worker keeps the sockets of dropped datagrams")

    def wait_fds_above(self, before, daemon=None):
        deadline = time.monotonic() + 5.0
        while self.fds(daemon) <= before and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertGreater(self.fds(daemon), before, "the worker did not get the TACACS+ connection")

    def udp_sockets(self, daemon):
        """(remote address, receive queue) of each socket on the UDP port; the remote address of the listener is None."""
        port = ":%04X" % daemon.udp_port
        found = []
        for name in ("/proc/net/udp", "/proc/net/udp6"):
            if os.path.exists(name):
                with open(name) as f:
                    rows = [line.split() for line in f.readlines()[1:]]
                # a reply socket of spawnd is connected to its client, the listener is not (remote port 0)
                found += [(None if r[2].endswith(":0000") else r[2], int(r[4].split(":")[1], 16)) for r in rows if r[1].endswith(port)]
        self.assertIn(None, [remote for remote, _ in found], "no UDP listener on port %d" % daemon.udp_port)
        return found

    def reply_sockets(self, daemon):
        return {remote for remote, _ in self.udp_sockets(daemon) if remote}

    def wait_udp_listener_read(self, daemon):
        """Wait until spawnd has read every datagram that waits on its UDP listener."""
        deadline = time.monotonic() + 5.0
        while any(q for remote, q in self.udp_sockets(daemon) if remote is None) and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertFalse(any(q for remote, q in self.udp_sockets(daemon) if remote is None), "spawnd did not read the datagrams")

    def assertReplySocketsClosed(self, before, daemon):
        """spawnd read every datagram, and of the reply sockets only those in before are left."""
        self.wait_udp_listener_read(daemon)
        deadline = time.monotonic() + 5.0
        while self.reply_sockets(daemon) - before and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(self.reply_sockets(daemon) - before, set(), "the worker keeps the sockets of dropped datagrams")

    def assertLruConnectionKept(self, body, datagram):
        """users_inc() at "last-recently-used limit" evicts the oldest context; a dropped datagram must not."""
        d = self.start_daemon(body + "\tlast-recently-used limit = 1\n", udp=True)
        before = self.fds(d)
        c = self.connect(daemon=d)
        self.wait_fds_above(before, d)
        self.radius(SECRET, daemon=d, source=NAS).send_raw(datagram)
        self.assertFalse(c.closed(timeout=2.0), "a dropped datagram evicted the TACACS+ connection")
        return c

    def test_same_source_port_is_answered_after_a_bad_datagram(self):
        c = self.radius(SECRET, source=NAS, timeout=1.0)
        self.bad(c)
        with self.assertRaises(TimeoutError):
            c.recv_raw()
        c.timeout = 5.0
        c.sock.settimeout(5.0)
        r = c.access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    @unittest.skipUnless(LINUX, "sockets through /proc")
    def test_bad_datagrams_leave_no_socket_open(self):
        before = self.reply_sockets(self.daemon)
        for _ in range(10):
            self.bad(self.radius(SECRET, source=NAS))
        self.assertReplySocketsClosed(before, self.daemon)

    @unittest.skipUnless(LINUX, "file descriptors through /proc")
    def test_datagrams_without_a_dictionary_leave_no_socket_open(self):
        d = self.start_daemon("", udp=True)
        with d.connect() as c:
            self.assertFalse(c.pap("nobody", "x").ok)  # opens authentication.log before the count
        # the first datagram gives the worker its copy of the listener, which it keeps
        self.radius(SECRET, daemon=d, source=NAS).send_raw(radius.Packet(radius.ACCESS_REQUEST).encode())
        self.wait_udp_listener_read(d)
        with d.connect() as c:
            self.assertFalse(c.pap("nobody", "x").ok)
        before = self.fds(d)
        for _ in range(10):
            req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
            self.radius(SECRET, daemon=d, source=NAS).send_raw(req.encode())
        # spawnd passes a datagram in the handler that reads it, so after this the datagrams are before the connection
        self.wait_udp_listener_read(d)
        # no RADIUS answer without a dictionary: a TACACS+ answer shows that the worker read its control socket
        with d.connect() as c:
            self.assertFalse(c.pap("nobody", "x").ok)
        self.assertFdsBack(before, d)

    @unittest.skipUnless(LINUX, "file descriptors through /proc")
    def test_bad_datagram_keeps_the_least_recently_used_connection(self):
        c = self.assertLruConnectionKept(POLICY, radius.Packet(radius.ACCESS_REQUEST).encode(length=200))
        self.assertTrue(c.pap("alice", "alicepw").ok)

    @unittest.skipUnless(LINUX, "file descriptors through /proc")
    def test_datagram_without_a_dictionary_keeps_the_least_recently_used_connection(self):
        self.assertLruConnectionKept("", radius.Packet(radius.ACCESS_REQUEST).encode())

    @unittest.skipUnless(LINUX, "sockets through /proc")
    def test_bad_datagrams_do_not_use_up_the_user_limit(self):
        """spawnd counts each passed datagram as a user until the worker reports it done."""
        d = self.start_daemon(POLICY, udp=True, spawnd="\tspawn { users max = 4 }\n")
        before = self.reply_sockets(d)
        for _ in range(6):
            self.bad(self.radius(SECRET, daemon=d, source=NAS))
        # a datagram that comes while spawnd binds a reply socket goes to that socket: wait until they are gone
        self.assertReplySocketsClosed(before, d)
        r = self.radius(SECRET, daemon=d, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)


class ConditionTypes(DaemonTestCase):
    """A condition on a "time" or "enum" attribute compares numbers, as for "integer"."""

    VENDOR = 99999
    MODE = 1
    EVENT_TIMESTAMP = 55
    SERVICE_TYPE = 6
    VENDOR_SPECIFIC = 26
    CONFIG = """
	include = "%s"
	radius.dictionary tactest %d {
		attribute Mode %d enum {
			On 1
			Off 2
			Max 4294967295
		}
	}
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (radius[Event-Timestamp] == 1234) set radius[Reply-Message] = "time"
			if (radius[tactest:Mode] == On) set radius[Reply-Message] = "enum by name"
			if (radius[tactest:Mode] == 2) set radius[Reply-Message] = "enum by number"
			if (radius[Service-Type] == Login-User) set radius[Reply-Message] = "integer"
			if (radius[Event-Timestamp] == 4294967295) set radius[Reply-Message] = "max time"
			if (radius[tactest:Mode] == Max) set radius[Reply-Message] = "max enum by name"
			if (radius[tactest:Mode] == 0x80000000) set radius[Reply-Message] = "high enum by number"
			if (radius[Event-Timestamp] == 1K) set radius[Reply-Message] = "scaled time"
			if (service == Callback-Login-User) set radius[Reply-Message] = "service by name"
			permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, VENDOR, MODE, SECRET)
    UDP = True

    def messages(self, *attributes):
        r = self.radius(SECRET, source=NAS).access_request("alice", "alicepw", attributes=attributes,
                                                           message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return r.get(radius.REPLY_MESSAGE)

    def mode(self, value):
        value = struct.pack("!I", value)
        vsa = bytes([self.MODE, 2 + len(value)]) + value
        return (self.VENDOR_SPECIFIC, struct.pack("!I", self.VENDOR) + vsa)

    def test_time(self):
        self.assertEqual(self.messages((self.EVENT_TIMESTAMP, struct.pack("!I", 1234))), [b"time"])
        self.assertEqual(self.messages((self.EVENT_TIMESTAMP, struct.pack("!I", 1235))), [])

    def test_enum_by_name(self):
        self.assertEqual(self.messages(self.mode(1)), [b"enum by name"])

    def test_enum_by_number(self):
        self.assertEqual(self.messages(self.mode(2)), [b"enum by number"])
        self.assertEqual(self.messages(self.mode(3)), [])

    def test_integer_still_compares(self):
        self.assertEqual(self.messages((self.SERVICE_TYPE, struct.pack("!I", 1))), [b"integer"])
        self.assertEqual(self.messages((self.SERVICE_TYPE, struct.pack("!I", 2))), [])

    def test_full_unsigned_range(self):
        self.assertEqual(self.messages((self.EVENT_TIMESTAMP, struct.pack("!I", 0xffffffff))), [b"max time"])
        self.assertEqual(self.messages(self.mode(0xffffffff)), [b"max enum by name"])
        self.assertEqual(self.messages(self.mode(0x80000000)), [b"high enum by number"])
        self.assertEqual(self.messages(self.mode(0x7fffffff)), [])

    def test_scaled_value(self):
        self.assertEqual(self.messages((self.EVENT_TIMESTAMP, struct.pack("!I", 1024))), [b"scaled time"])
        self.assertEqual(self.messages((self.EVENT_TIMESTAMP, struct.pack("!I", 1))), [])

    def test_service_from_service_type(self):
        """The Service-Type value names the service; the lookup started at value 6, so 1 to 5 got no name."""
        self.assertEqual(self.messages((self.SERVICE_TYPE, struct.pack("!I", 3))), [b"service by name"])
        self.assertEqual(self.messages((self.SERVICE_TYPE, struct.pack("!I", 4))), [])


class NumberOutOfRange(unittest.TestCase):
    """A RADIUS number above 4294967295 wrapped silently, "4294967296" compared as 0."""

    def error_of(self, value, condition_value="1"):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "range.cfg")
            with open(path, "w") as f:
                f.write("""id = spawnd { listen = { port = 4949 } }
id = tac_plus-ng {
	include = "%s"
	radius.dictionary tactest 99999 {
		attribute Mode 1 enum {
			On %s
		}
	}
	profile admin {
		script {
			if (radius[Event-Timestamp] == %s) permit
		}
	}
}
""" % (DICTIONARY, value, condition_value))
            code, out = parse_only(path)
            self.assertGreater(code, 0, out)
            return out

    def test_condition_value(self):
        self.assertIn("expected an unsigned integer from 0 to 4294967295, but got '4294967296'",
                      self.error_of("1", "4294967296"))

    def test_condition_value_with_suffix(self):
        self.assertIn("expected an unsigned integer from 0 to 4294967295, but got '4G'", self.error_of("1", "4G"))
        self.assertIn("expected an unsigned integer from 0 to 4294967295, but got '1Kjunk'",
                      self.error_of("1", "1Kjunk"))

    def test_condition_hex_value(self):
        self.assertIn("expected an unsigned integer from 0 to 4294967295, but got '0x100000000'",
                      self.error_of("1", "0x100000000"))

    def test_dictionary_value(self):
        self.assertIn("expected an unsigned integer from 0 to 4294967295, but got '4294967296'",
                      self.error_of("4294967296"))


class DictionaryFormat(unittest.TestCase):
    """A dictionary "format" outside the sizes of FreeRADIUS shifted by 32 bits or more."""

    def parse(self, fmt, attribute="Mode 1"):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "format.cfg")
            with open(path, "w") as f:
                f.write("""id = spawnd { listen = { port = 4949 } }
id = tac_plus-ng {
	radius.dictionary tactest 99999 format = %s {
		attribute %s integer
	}
}
""" % (fmt, attribute))
            return parse_only(path)

    def error_of(self, fmt, attribute="Mode 1"):
        code, out = self.parse(fmt, attribute)
        self.assertGreater(code, 0, out)
        return out

    def test_attribute_bytes(self):
        for fmt, value in (("3, 1", "3"), ("5, 1", "5"), ("4294967295, 1", "4294967295")):
            self.assertIn("expected 1, 2 or 4 attribute bytes, but got '%s'" % value, self.error_of(fmt))
        self.assertIn("expected an unsigned integer from 0 to 4294967295, but got '4294967296'",
                      self.error_of("4294967296, 1"))

    def test_length_bytes(self):
        self.assertIn("expected 0, 1 or 2 length bytes, but got '3'", self.error_of("1, 3"))

    def test_four_attribute_bytes(self):
        """"format = 4, 1" rejected every attribute number."""
        code, out = self.parse("4, 1", "Big 70000")
        self.assertEqual(code, 0, out)

    def test_attribute_above_the_attribute_bytes(self):
        self.assertIn("Expected a number from 1 to 65535 but got '65536'",
                      self.error_of("2, 1", "Big 65536"))


class ConditionWithoutNamedValues(unittest.TestCase):
    """A name for an attribute that has no named values dereferenced a NULL value."""

    def error_of(self, attribute):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cond.cfg")
            with open(path, "w") as f:
                f.write("""id = spawnd { listen = { port = 4949 } }
id = tac_plus-ng {
	include = "%s"
	profile admin {
		script {
			if (radius[%s] == bogus) permit
		}
	}
}
""" % (DICTIONARY, attribute))
            code, out = parse_only(path)
            self.assertGreater(code, 0, out)
            return out

    def test_integer(self):
        self.assertIn("RADIUS attribute 'NAS-Port' has no named values", self.error_of("NAS-Port"))

    def test_time(self):
        self.assertIn("RADIUS attribute 'Event-Timestamp' has no named values", self.error_of("Event-Timestamp"))


def condition_error(test, condition):
    """The output of a parse-only run of a profile script with this condition; the parse must fail."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cond.cfg")
        with open(path, "w") as f:
            f.write("""id = spawnd { listen = { port = 4949 } }
id = tac_plus-ng {
	include = "%s"
	radius.dictionary tactest 99999 {
		attribute Mode 1 enum {
			On 1
		}
	}
	profile admin {
		script {
			if (%s) permit
		}
	}
}
""" % (DICTIONARY, condition))
        code, out = parse_only(path)
        test.assertGreater(code, 0, out)
        return out


class RegexOnNumericAttribute(unittest.TestCase):
    """A regex on a number compared the value with the pointer to the compiled regex."""

    def error_of(self, condition):
        return condition_error(self, condition)

    def test_integer(self):
        self.assertIn("REGEX matching isn't supported for numeric RADIUS attribute 'NAS-Port'",
                      self.error_of("radius[NAS-Port] =~ /1/"))

    def test_time(self):
        self.assertIn("REGEX matching isn't supported for numeric RADIUS attribute 'Event-Timestamp'",
                      self.error_of("radius[Event-Timestamp] =~ /1/"))

    def test_enum(self):
        self.assertIn("REGEX matching isn't supported for numeric RADIUS attribute 'Mode'",
                      self.error_of("radius[tactest:Mode] =~ /1/"))

    def test_negated_posix_regex(self):
        self.assertIn("REGEX matching isn't supported for numeric RADIUS attribute 'NAS-Port'",
                      self.error_of('radius[NAS-Port] !~ "1"'))


class RegexOnOtherAttributes(DaemonTestCase):
    """A regex on a string or address attribute matches its text."""

    NAS_IP_ADDRESS = 4
    CONFIG = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (radius[User-Name] =~ /^ali/) set radius[Reply-Message] = "pcre"
			if (radius[User-Name] =~ "^ali") set radius[Reply-Message] = "posix"
			if (radius[User-Name] =~ /^bob/) set radius[Reply-Message] = "other name"
			if (radius[NAS-IP-Address] =~ /^10[.]0[.]0[.]1/) set radius[Reply-Message] = "address"
			permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)
    UDP = True

    def messages(self, *attributes):
        r = self.radius(SECRET, source=NAS).access_request("alice", "alicepw", attributes=attributes,
                                                           message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return r.get(radius.REPLY_MESSAGE)

    def test_string(self):
        self.assertEqual(self.messages(), [b"pcre", b"posix"])

    def test_address(self):
        self.assertEqual(self.messages((self.NAS_IP_ADDRESS, bytes([10, 0, 0, 1]))), [b"pcre", b"posix", b"address"])
        self.assertEqual(self.messages((self.NAS_IP_ADDRESS, bytes([10, 0, 0, 2]))), [b"pcre", b"posix"])


class EqualOnOtherAttributes(DaemonTestCase):
    """"==" and "!=" on a string or address attribute compare its text."""

    NAS_IP_ADDRESS = 4
    CONFIG = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (radius[User-Name] == alice) set radius[Reply-Message] = "name is alice"
			if (radius[User-Name] == bob) set radius[Reply-Message] = "name is bob"
			if (radius[User-Name] != alice) set radius[Reply-Message] = "name is not alice"
			if (radius[User-Name] != bob) set radius[Reply-Message] = "name is not bob"
			if (radius[NAS-IP-Address] == 10.0.0.1) set radius[Reply-Message] = "address is 10.0.0.1"
			if (radius[NAS-IP-Address] != 10.0.0.1) set radius[Reply-Message] = "address is not 10.0.0.1"
			permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)
    UDP = True

    def messages(self, *attributes):
        r = self.radius(SECRET, source=NAS).access_request("alice", "alicepw", attributes=attributes,
                                                           message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return r.get(radius.REPLY_MESSAGE)

    def test_string(self):
        self.assertEqual(self.messages()[:2], [b"name is alice", b"name is not bob"])

    def test_address(self):
        self.assertEqual(self.messages((self.NAS_IP_ADDRESS, bytes([10, 0, 0, 1])))[2:], [b"address is 10.0.0.1"])
        self.assertEqual(self.messages((self.NAS_IP_ADDRESS, bytes([10, 0, 0, 2])))[2:], [b"address is not 10.0.0.1"])

    def test_missing_attribute_is_not_equal(self):
        self.assertEqual(self.messages()[2:], [b"address is not 10.0.0.1"])


class EqualOnIpv6Address(DaemonTestCase):
    """A missing IPv6 attribute compared as "::"."""

    NAS_IPV6_ADDRESS = 95
    CONFIG = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (radius[NAS-IPv6-Address] == "::") set radius[Reply-Message] = "address is ::"
			if (radius[NAS-IPv6-Address] == "2001:db8::1") set radius[Reply-Message] = "address is 2001:db8::1"
			if (radius[NAS-IPv6-Address] != "2001:db8::1") set radius[Reply-Message] = "address is not 2001:db8::1"
			permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)
    UDP = True

    def messages(self, *attributes):
        r = self.radius(SECRET, source=NAS).access_request("alice", "alicepw", attributes=attributes,
                                                           message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return r.get(radius.REPLY_MESSAGE)

    def test_address(self):
        address = bytes.fromhex("20010db8000000000000000000000001")
        self.assertEqual(self.messages((self.NAS_IPV6_ADDRESS, address)), [b"address is 2001:db8::1"])

    def test_unspecified_address(self):
        self.assertEqual(self.messages((self.NAS_IPV6_ADDRESS, bytes(16))),
                         [b"address is ::", b"address is not 2001:db8::1"])

    def test_missing_attribute_is_not_equal(self):
        self.assertEqual(self.messages(), [b"address is not 2001:db8::1"])


class StringWithNul(DaemonTestCase):
    """A string attribute "abc\\0suffix" compared equal to "abc": strcmp() and regexec() stop at the NUL."""

    CALLING_STATION_ID = 31
    CONFIG = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (radius[Calling-Station-Id] == abc) set radius[Reply-Message] = "equal"
			if (radius[Calling-Station-Id] != abc) set radius[Reply-Message] = "not equal"
			if (radius[Calling-Station-Id] =~ "^abc$$") set radius[Reply-Message] = "posix"
			if (radius[Calling-Station-Id] =~ /^abc$$/) set radius[Reply-Message] = "pcre"
			if (radius[Calling-Station-Id] =~ /suffix$$/) set radius[Reply-Message] = "pcre suffix"
			permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)
    UDP = True

    def messages(self, value):
        r = self.radius(SECRET, source=NAS).access_request("alice", "alicepw",
                                                           attributes=[(self.CALLING_STATION_ID, value)],
                                                           message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return r.get(radius.REPLY_MESSAGE)

    def test_without_nul(self):
        self.assertEqual(self.messages(b"abc"), [b"equal", b"posix", b"pcre"])

    def test_with_nul(self):
        self.assertEqual(self.messages(b"abc\0suffix"), [b"not equal", b"pcre suffix"])


class ConditionOnOctetsOrVsa(unittest.TestCase):
    """A condition on an "octets" or "vsa" attribute had no text to compare and never matched."""

    def test_equal_on_octets(self):
        self.assertIn("Conditions aren't supported for RADIUS attribute 'State' (type octets)",
                      condition_error(self, "radius[State] == abc"))

    def test_not_equal_on_octets(self):
        self.assertIn("Conditions aren't supported for RADIUS attribute 'State' (type octets)",
                      condition_error(self, "radius[State] != abc"))

    def test_regex_on_octets(self):
        self.assertIn("Conditions aren't supported for RADIUS attribute 'State' (type octets)",
                      condition_error(self, "radius[State] =~ /abc/"))

    def test_vendor_octets(self):
        self.assertIn("Conditions aren't supported for RADIUS attribute 'MS-CHAP-Challenge' (type octets)",
                      condition_error(self, "radius[Microsoft:MS-CHAP-Challenge] == abc"))

    def test_vsa(self):
        self.assertIn("Conditions aren't supported for RADIUS attribute 'Vendor-Specific' (type vsa)",
                      condition_error(self, "radius[Vendor-Specific] == abc"))


class RealmOnUdpListener(DaemonTestCase):
    """#232: "realm =" on a UDP listener was ignored, every RADIUS request went to the default realm.

    struct scm_data_accept and scm_data_udp had their members in a different
    order (mavis/scm.h), so the worker read the realm name from the wrong
    place. The device and the user exist in realm "radius" only.
    """

    LISTEN = {"udp": "protocol = UDP realm = radius", "tcp": "realm = radius"}
    CONFIG = """
	include = "%s"
	realm radius {
		device radius-nas {
			address = 127.0.0.6
			radius.key = %s
		}
		user bob {
			password login = clear bobpw
			password pap = login
		}
		ruleset {
			rule { script { permit } }
		}
	}
""" % (DICTIONARY, SECRET)

    def test_issue232_realm_of_a_udp_listener(self):
        r = self.radius(SECRET, listener="udp", source=NAS).access_request("bob", "bobpw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_issue232_realm_of_a_tcp_listener(self):
        r = self.radius(SECRET, listener="tcp", tcp=True, source=NAS).access_request("bob", "bobpw",
                                                                                     message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)


class ProtocolProbes:
    """One TACACS+ PAP, RADIUS over UDP or RADIUS/TCP request to a listener; DaemonTestCase mixin."""

    def tacacs_answers(self, listener=None):
        return self.connect(listener=listener).pap("alice", "alicepw").ok

    def tacacs_refused(self, listener):
        c = self.connect(listener=listener, timeout=CLOSE_TIMEOUT)
        c.send(tacacs.Packet.authen_start(user="alice"))
        return c.closed()

    def radius_udp(self, listener=None):
        c = self.radius(SECRET, listener=listener, source=NAS, timeout=2.0)
        return c.access_request("alice", "alicepw", message_authenticator=True).code_name

    def radius_tcp(self, listener=None):
        c = self.radius(SECRET, tcp=True, listener=listener, source=NAS, timeout=CLOSE_TIMEOUT)
        return c.access_request("alice", "alicepw", message_authenticator=True).code_name

    def assert_radius_refused(self, request, listener):
        with self.assertRaises((TimeoutError, ConnectionError)):
            request(listener)


class AaaProtocolAllowed(ProtocolProbes, DaemonTestCase):
    """aaa.protocol.allowed in a realm: a protocol not in the list gets no answer.

    CHECK_PROTOCOL in packet.c rejected only if the protocol of the
    connection was already known, which it never is at the first packet,
    so every protocol was answered. Realm "inherited" has no keyword of its
    own and gets the list of its parent, realm "override" replaces that
    list with its own. The default realm has no keyword and answers all
    protocols (the default listeners).

    #342: a refusal is a CONN-REJECT record of the connection log, with
    the protocol as its hint; it was a plain CONN-STOP (TCP) or nothing
    (UDP), so nothing on the server told why a device got no answer.
    """

    UDP = True
    LISTEN = {
        "tacacs-only": "realm = tacacs-only",
        "tacacs-only-udp": "protocol = UDP realm = tacacs-only",
        "radius-udp-only": "realm = radius-udp-only",
        "radius-udp-only-udp": "protocol = UDP realm = radius-udp-only",
        "radius-tcp-only": "realm = radius-tcp-only",
        "radius-tcp-only-udp": "protocol = UDP realm = radius-tcp-only",
        "inherited": "realm = inherited",
        "inherited-udp": "protocol = UDP realm = inherited",
        "override": "realm = override",
        "override-udp": "protocol = UDP realm = override",
    }
    CONFIG = POLICY + """
	log connection {
		destination = "$tmp/connection.log"
		connection format = "$${msgid}$${FS}$${realm}$${FS}$${hint}"
	}
	connection log = connection
	realm tacacs-only {
		aaa.protocol.allowed = tacacs.tcp
		realm inherited { }
		realm override { aaa.protocol.allowed = radius.udp }
	}
	realm radius-udp-only { aaa.protocol.allowed = radius.udp }
	realm radius-tcp-only { aaa.protocol.allowed = radius.tcp }
"""

    def test_tacacs_only(self):
        self.assertTrue(self.tacacs_answers("tacacs-only"))
        self.assert_radius_refused(self.radius_udp, "tacacs-only-udp")
        self.assert_radius_refused(self.radius_tcp, "tacacs-only")

    def test_radius_udp_only(self):
        self.assertEqual(self.radius_udp("radius-udp-only-udp"), "Access-Accept")
        self.assertTrue(self.tacacs_refused("radius-udp-only"))
        self.assert_radius_refused(self.radius_tcp, "radius-udp-only")

    def test_radius_tcp_only(self):
        self.assertEqual(self.radius_tcp("radius-tcp-only"), "Access-Accept")
        self.assertTrue(self.tacacs_refused("radius-tcp-only"))
        self.assert_radius_refused(self.radius_udp, "radius-tcp-only-udp")

    def test_inherited_from_the_parent_realm(self):
        self.assertTrue(self.tacacs_answers("inherited"))
        self.assert_radius_refused(self.radius_udp, "inherited-udp")

    def test_realm_without_the_keyword_answers_all(self):
        self.assertTrue(self.tacacs_answers())
        self.assertEqual(self.radius_udp(), "Access-Accept")
        self.assertEqual(self.radius_tcp(), "Access-Accept")

    def test_child_realm_replaces_the_list_of_its_parent(self):
        self.assertEqual(self.radius_udp("override-udp"), "Access-Accept")
        self.assertTrue(self.tacacs_refused("override"))

    def assert_reject_logged(self, realm, protocol):
        self.wait_log("connection", "CONN-REJECT\t%s\t%s not in aaa.protocol.allowed\n" % (realm, protocol))

    def test_refused_tacacs_is_in_the_connection_log(self):
        self.assertTrue(self.tacacs_refused("radius-udp-only"))
        self.assert_reject_logged("radius-udp-only", "tacacs.tcp")

    def test_refused_radius_tcp_is_in_the_connection_log(self):
        self.assert_radius_refused(self.radius_tcp, "tacacs-only")
        self.assert_reject_logged("tacacs-only", "radius.tcp")

    def test_refused_radius_udp_is_in_the_connection_log(self):
        self.assert_radius_refused(self.radius_udp, "inherited-udp")
        self.assert_reject_logged("inherited", "radius.udp")


TRACE_CONFIG = """\
id = spawnd { listen { port = 4949 } }
id = tac_plus-ng {
	device all {
		address = 0.0.0.0/0
		key = tactest
	}
	user alice { password login = clear alicepw }
	profile admin { script { if (service == shell) permit } }
	ruleset { rule { script { profile = admin permit } } }
	realm tcp-only { aaa.protocol.allowed = tacacs.tcp }
	realm tls-only { aaa.protocol.allowed = tacacs.tls }
	realm radius-only { aaa.protocol.allowed = radius }
}
"""


@unittest.skipUnless(LINUX, "descriptor passing as tactrace.pl does it on Linux")
class AaaProtocolAllowedTactrace(DaemonTestCase):
    """#342: tactrace.pl tests the rules of a realm whatever aaa.protocol.allowed says.

    tactrace.pl starts tac_plus-ng without spawnd ("-d 4194304", the
    tactrace debug flag), takes the place of spawnd on its standard
    input and hands it one end of a stream socket pair (SCM_ACCEPT, with
    the realm), then sends a PROXY v2 header and the request. That
    connection is plain TACACS+ always, so since the realm list is
    enforced a realm without tacacs.tcp could not be traced any more.
    This test does the same without Perl.
    """

    CONFIG = None
    SCM_ACCEPT, SCM_FLAG_HAPROXY = 6, 1     # mavis/scm.h

    def trace(self, realm):
        cfg = self.scratch_file("tactrace.cfg", TRACE_CONFIG)
        ctl, ctl_daemon = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        conn, conn_daemon = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        proc = subprocess.Popen([binary(), "-Dd", "802", "-d", "4194304", cfg, "tac_plus-ng"], stdin=ctl_daemon,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=sanitizer_env())
        ctl_daemon.close()
        try:
            # struct scm_data_accept: type, tls_versions, aaa_protocol, flags, realm[16], socktype, protocol
            accept = struct.pack("iIiI16sii", self.SCM_ACCEPT, 0, 0, self.SCM_FLAG_HAPROXY, realm.encode(), 0, 0)
            ctl.sendmsg([accept], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", conn_daemon.fileno()))])
            conn_daemon.close()
            conn.sendall(tacacs.proxy_v2("127.0.0.1", "127.0.0.1"))
            c = tacacs.Connection(("127.0.0.1", 0), "tactest", sock=conn, timeout=10.0)
            c.tls, c.key = False, b"tactest"    # sock= is for TLS sockets; this one is plain
            try:
                return c.author("alice", ["service=shell", "cmd*"]).status_name
            except tacacs.Closed:
                return "closed"
        finally:
            conn.close()
            ctl.close()
            proc.kill()
            proc.wait()

    def test_trace_of_a_realm(self):
        for realm in ("tcp-only", "tls-only", "radius-only"):
            with self.subTest(realm=realm):
                self.assertEqual(self.trace(realm), "PASS_ADD")


class ListenerAaaProtocol(ProtocolProbes, DaemonTestCase):
    """aaa.protocol in a spawnd listen block: that listener answers only that protocol.

    spawnd sent the value to the worker, but the worker did not read it, so
    every listener answered every protocol. The realm allows all protocols.
    """

    UDP = True
    LISTEN = {
        "tacacs-tcp": "aaa.protocol = tacacs.tcp",
        "radius-tcp": "aaa.protocol = radius.tcp",
        "radius-udp-on-tcp": "aaa.protocol = radius.udp",
        "radius-udp": "protocol = UDP aaa.protocol = radius.udp",
        "radius-tcp-on-udp": "protocol = UDP aaa.protocol = radius.tcp",
    }
    CONFIG = POLICY

    def test_tacacs_tcp(self):
        self.assertTrue(self.tacacs_answers("tacacs-tcp"))
        self.assert_radius_refused(self.radius_tcp, "tacacs-tcp")

    def test_radius_tcp(self):
        self.assertEqual(self.radius_tcp("radius-tcp"), "Access-Accept")
        self.assertTrue(self.tacacs_refused("radius-tcp"))

    def test_radius_udp(self):
        self.assertEqual(self.radius_udp("radius-udp"), "Access-Accept")

    def test_other_protocol_on_the_transport(self):
        self.assertTrue(self.tacacs_refused("radius-udp-on-tcp"))
        self.assert_radius_refused(self.radius_tcp, "radius-udp-on-tcp")
        self.assert_radius_refused(self.radius_udp, "radius-tcp-on-udp")

    def test_listener_without_the_keyword_answers_all(self):
        self.assertTrue(self.tacacs_answers())
        self.assertEqual(self.radius_udp(), "Access-Accept")
        self.assertEqual(self.radius_tcp(), "Access-Accept")


# no device for 127.0.0.2: the base configuration covers all of 127/8, NAS is 127.0.0.6
UNKNOWN_HOSTS = config.BASE.replace("address = 127.0.0.0/8", "address = 127.0.0.1/32")


class UnknownValue(unittest.TestCase):
    def test_set_with_an_unknown_value_names_value_and_attribute(self):
        """The format had '$s' for '%s', so the value appeared as the attribute and the attribute not at all."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "value.cfg")
            with open(path, "w") as f:
                f.write("""id = spawnd { listen = { port = 4949 } }
id = tac_plus-ng {
	include = "%s"
	profile admin {
		script {
			set radius[Service-Type] = bogus
			permit
		}
	}
}
""" % DICTIONARY)
            code, out = parse_only(path)
            self.assertGreater(code, 0, out)
            self.assertIn("RADIUS value 'bogus' not found (attribute: Service-Type)", out)


class UnknownHost(DaemonTestCase):
    """#247: a request from an address without a device crashed the worker (builds without OpenSSL)."""

    CONFIG = None

    def start(self):
        self.assertNotEqual(UNKNOWN_HOSTS, config.BASE, "config.BASE no longer has address = 127.0.0.0/8")
        return self.start_daemon(POLICY, template=UNKNOWN_HOSTS, udp=True)

    def test_issue247_radius_from_unknown_host(self):
        d = self.start()
        with d.radius(SECRET, source="127.0.0.2", timeout=2.0) as c:
            with self.assertRaises(TimeoutError):
                c.access_request("alice", "alicepw")

    def test_issue247_tacacs_from_unknown_host(self):
        d = self.start()
        with d.connect(source="127.0.0.2", timeout=2.0) as c:
            c.send(tacacs.Packet.authen_start(user="alice"))
            self.assertTrue(c.closed(), "the daemon answered a device it doesn't know")


VENDOR_SPECIFIC = 26
CISCO_VENDOR = 9
ACL_DOWNLOAD = b"aaa:event=acl-download"

DACLS = """
	dacl acl-voice { data = "permit ip any any" }
	dacl demoacl { data = "permit ip any any" }
	log rad-access { destination = "$tmp/rad-access.log" }
	radius.access log = rad-access
"""


class DaclName:
    """A dACL download "#ACSACL#<name>-<version>" gets the static dACL <name>; DaemonTestCase mixin.

    do_radius_dacl() cut the name at the last hyphen, also when there was
    none: str_set() then got the length NULL - name, and the access log
    read past the end of the user name. With "user backend = mavis", a
    MAVIS answer other than OK runs the handler a second time, on the name
    already cut: "acl-voice" became "acl", "demoacl" had no hyphen left.
    """

    UDP = True

    def download(self, user, name):
        off = self.daemon.log_size("rad-access")
        r = self.radius(SECRET, source=NAS).access_request(
            user, "", message_authenticator=True,
            attributes=[(VENDOR_SPECIFIC, struct.pack("!IBB", CISCO_VENDOR, 1, len(ACL_DOWNLOAD) + 2) + ACL_DOWNLOAD)])
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertIn(b"ip:inacl#1=permit ip any any", b"".join(r.get(VENDOR_SPECIFIC)), r)
        log = self.daemon.wait_log("rad-access", "User-Name=%s " % user, offset=off)
        line = next(line for line in log.splitlines() if "User-Name=%s " % user in line)
        self.assertEqual(line.split("\t")[1], name, line)
        self.assertIn("dacl request succeeded", line)

    def test_hyphen_in_the_name(self):
        self.download("#ACSACL#acl-voice-00000000", "acl-voice")

    def test_no_hyphen_in_the_name(self):
        self.download("#ACSACL#demoacl-00000000", "demoacl")

    def test_no_version(self):
        self.download("#ACSACL#demoacl", "demoacl")


class DaclNameStatic(DaclName, DaemonTestCase):
    CONFIG = POLICY + DACLS


class DaclNameBackendNotFound(DaclName, DaemonTestCase):
    """The MAVIS backend doesn't know the dACL (NOTFOUND): the static one is used."""

    CONFIG = Stub.module(childs=(1, 1)) + POLICY + DACLS + "\tuser backend = mavis\n"

    def download(self, user, name):
        stub = Stub(self.daemon)
        before = stub.count()
        super().download(user, name)
        self.assertEqual([(e["type"], e["user"], e["result"]) for e in stub.requests()[before:]],
                         [("DACL", name, "NOTFOUND")])


class DaclNameNoMavisModule(DaclName, DaemonTestCase):
    """No MAVIS module, but "user backend = mavis": the static dACL is used."""

    CONFIG = POLICY + DACLS + "\tuser backend = mavis\n"


if __name__ == "__main__":
    unittest.main()
