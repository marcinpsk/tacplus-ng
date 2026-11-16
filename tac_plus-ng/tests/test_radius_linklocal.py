"""RADIUS/UDP from IPv6 link-local clients: one address and port on two interfaces are two clients.

The interface is the scope of a link-local address (sin6_scope_id). spawnd
and the worker compared the addresses of two clients without it, so the
second client got the context of the first, and its reply went to the
first client.

The tests need two interfaces with the same link-local addresses. They
run again in a user and network namespace of their own ("unshare --user
--net --map-root-user"), where root of the namespace can make two dummy
devices; both have fe80::1 (the clients) and fe80::2 (the server). The
whole test process is in the namespace, so the crash detectors see the
daemon as in every other test.
"""

import os
import shutil
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


def setUpModule():
    if os.environ.get(NETNS):
        subprocess.run(["ip", "-batch", "-"], input=NETWORK.encode(), check=True)


def namespace_problem():
    """Why no namespace with dummy devices can be made here, or None."""
    if not LINUX:
        return "Linux only"
    for tool in ("unshare", "ip"):
        if not shutil.which(tool):
            return "no %s command" % tool
    p = subprocess.run(UNSHARE + ["ip", "link", "add", "ll0", "type", "dummy"], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=30, check=False)
    if p.returncode:
        return "no dummy device in a user namespace: " + p.stdout.decode("utf-8", "replace").strip()
    return None


class Namespace(unittest.TestCase):
    def test_link_local_tests_in_a_network_namespace(self):
        problem = namespace_problem()
        if problem:
            self.skipTest(problem)
        p = subprocess.run(UNSHARE + [sys.executable, "-m", "unittest", "-v", MODULE + ".LinkLocal"],
                           cwd=os.path.dirname(os.path.abspath(__file__)), env=dict(os.environ, **{NETNS: "1"}),
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
                           check=False)
        out = p.stdout.decode("utf-8", "replace")
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
            r = radius.Packet.decode(s.recvfrom(65535)[0])
        except socket.timeout:
            self.fail("no reply for the client on %s" % device)
        self.assertEqual((r.code_name, r.identifier), ("Access-Accept", req.identifier))

    def test_same_address_and_port_on_two_interfaces(self):
        port = free_udp_port("::")
        self.start_daemon(POLICY, spawnd="\tlisten { address = :: port = %d protocol = UDP }\n" % port)
        first = self.client(DEVICES[0], 0)
        second = self.client(DEVICES[1], first.getsockname()[1])
        for s, device in ((first, DEVICES[0]), (second, DEVICES[1]), (first, DEVICES[0]), (second, DEVICES[1])):
            self.access_request(s, device, port)
