"""RADIUS/UDP from IPv6 link-local clients.

The interface is the scope of a link-local address (sin6_scope_id). spawnd
binds the reply socket to the destination address of the datagram; for a
link-local address, bind() needs its scope too.

The tests need an interface with link-local addresses. They run again in
a user and network namespace of their own ("unshare --user --net
--map-root-user"), where root of the namespace can make dummy devices;
each has fe80::1 (the clients) and fe80::2 (the server). The whole test
process is in the namespace, so the crash detectors see the daemon as in
every other test.
"""

import os
import shutil
import signal
import socket
import subprocess
import sys
import unittest

from tactest import LINUX, SOURCE, DaemonTestCase, radius
from tactest.daemon import free_udp_port

NETNS = "TACTEST_LINKLOCAL_NETNS"
UNSHARE = ["unshare", "--user", "--net", "--map-root-user"]
MODULE = os.path.splitext(os.path.basename(__file__))[0]
DEVICES = ("ll0", "ll1")
CLIENT, SERVER = "fe80::1", "fe80::2"
SECRET = "radsecret"

NETWORK = "link set lo up\n" + "".join(
    "link add %s type dummy\nlink set %s up\naddr add %s/64 dev %s nodad\naddr add %s/64 dev %s nodad\n"
    % (d, d, CLIENT, d, SERVER, d) for d in DEVICES)

POLICY = """
	include = "%s"
	device link-local {
		address = fe80::/10
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	ruleset {
		rule { script { permit } }
	}
""" % (os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg"), SECRET)


def fresh_namespace():
    """True in a network namespace that nothing has set up: lo, down, is its only interface."""
    return socket.if_nameindex() == [(1, "lo")] and not subprocess.run(
        ["ip", "-o", "link", "show", "up"], stdout=subprocess.PIPE, check=True).stdout.strip()


def setUpModule():
    # never in the namespace of the caller, also if NETNS came from the environment
    if os.environ.get(NETNS) and LINUX and fresh_namespace():
        subprocess.run(["ip", "-batch", "-"], input=NETWORK.encode(), check=True)


def namespace_problem():
    """Why no namespace with dummy devices can be made here, or None."""
    if not LINUX:
        return "Linux only"
    for tool in ("unshare", "ip"):
        if not shutil.which(tool):
            return "no %s command" % tool
    # the IPv6 address too: a kernel without IPv6 makes the device, but not the address
    probe = b"link add ll0 type dummy\naddr add fe80::1/64 dev ll0 nodad\n"
    p = subprocess.run(UNSHARE + ["ip", "-batch", "-"], input=probe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=30, check=False)
    if p.returncode:
        return "no dummy device with IPv6 in a user namespace: " + p.stdout.decode("utf-8", "replace").strip()
    return None


class Namespace(unittest.TestCase):
    def test_link_local_tests_in_a_network_namespace(self):
        problem = namespace_problem()
        if problem:
            self.skipTest(problem)
        # a session of its own: at the timeout, the daemon of the child goes too, and with it the namespace
        p = subprocess.Popen(UNSHARE + [sys.executable, "-m", "unittest", "-v", MODULE + ".LinkLocal"],
                             cwd=os.path.dirname(os.path.abspath(__file__)), env=dict(os.environ, **{NETNS: "1"}),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
        try:
            out = p.communicate(timeout=300)[0].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            raise
        self.assertEqual(p.returncode, 0, "link-local tests in the namespace failed:\n" + out)
        self.assertNotIn("skipped", out, out)
        self.assertRegex(out, r"\nRan [1-9]", out)


@unittest.skipUnless(os.environ.get(NETNS), "runs in the namespace of Namespace")
class LinkLocal(DaemonTestCase):
    CONFIG = None

    def client(self, device, port):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.addCleanup(s.close)
        s.bind((CLIENT, port, 0, socket.if_nametoindex(device)))
        s.settimeout(5.0)
        return s

    def access_request(self, s, device, port):
        req = radius.Packet(radius.ACCESS_REQUEST)
        req.attributes = [(radius.USER_NAME, b"alice"),
                          (radius.USER_PASSWORD, radius.encrypt_password("alicepw", SECRET, req.authenticator))]
        s.sendto(req.encode(SECRET, message_authenticator=True), (SERVER, port, 0, socket.if_nametoindex(device)))
        try:
            data, sender = s.recvfrom(65535)
        except socket.timeout:
            self.fail("no reply for the client on %s" % device)
        # a connected RADIUS client takes a reply only from the address and port it sent to
        self.assertEqual((sender[0].split("%")[0], sender[1], sender[3]), (SERVER, port, socket.if_nametoindex(device)))
        r = radius.Packet.decode(data)
        self.assertEqual((r.code_name, r.identifier), ("Access-Accept", req.identifier))

    def test_link_local_destination(self):
        port = free_udp_port("::")
        self.start_daemon(POLICY, spawnd="\tlisten { address = :: port = %d protocol = UDP }\n" % port)
        self.access_request(self.client(DEVICES[0], 0), DEVICES[0], port)
