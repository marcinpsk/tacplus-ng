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


"""TACACS+ over TLS (RFC 9887), TLS 1.3 PSK, RADIUS over TLS and over DTLS.

The certificates come from a CA made for the test class (tactest.tls.CA,
the openssl command); nothing is kept in the tree. Skipped without the
openssl command or in a build without OpenSSL.
"""

import os
import select
import socket
import ssl
import struct
import threading
import time
import unittest

from tactest import LINUX, SOURCE, DaemonTestCase, Stub, cpu_seconds, features, radius, tacacs, tls

TLS_REALM = """
	tls cert-file = "%(server_crt)s"
	tls key-file = "%(server_key)s"
	tls ca-file = "%(ca)s"
"""

DEVICES = """
	device certnas.tactest {
		welcome banner = "certnas\\n"
	}
	device ipnas {
		address = 127.0.0.9
		key = ipkey
		tls.peer.cert.validation = none
	}
"""


def policy(devices=("certnas.tactest", "ipnas", "localhost")):
    """alice; shell authorization answers which device and transport the daemon saw, as tactest-* AV pairs."""
    lines = "".join("\t\t\t\tif (device.name == %s) set tactest-device = %s\n" % (d, d.split(".")[0])
                    for d in devices)
    return """
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile shell {
		script {
			if (service == shell) {
%s				if (conn.transport == tls) set tactest-transport = tls
				if (conn.transport == tcp) set tactest-transport = tcp
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
""" % lines


POLICY = DEVICES + policy()


def need_tls():
    if not tls.openssl_available():
        raise unittest.SkipTest("no openssl command to make certificates")
    if "openssl" not in features():
        raise unittest.SkipTest("tac_plus-ng built without OpenSSL")


class TlsTestCase(DaemonTestCase):
    """A daemon with a CA of its own; CONFIG is formatted with the paths of its certificates.

    CLIENTS maps a name to the subject of its client certificate, or to
    (subject, subjectAltName), or to (subject, subjectAltName, aki) where
    aki is the authorityKeyIdentifier form (see tls.CA.issue). BODY =
    None: the tests start their own daemons (cls.paths for the
    certificates).
    """

    BODY = ""
    CLIENTS = {"certnas": "/CN=certnas.tactest", "nobody": "/CN=nobody.tactest"}

    @classmethod
    def setUpClass(cls):
        need_tls()
        cls.ca = tls.CA(cls.__name__ + "-ca")
        cls.certs = {}
        for name, spec in cls.CLIENTS.items():
            subject, san, aki = (spec, None, "keyid") if isinstance(spec, str) else (spec + ("keyid",))[:3]
            cls.certs[name] = cls.ca.issue(name, subject, san=san, aki=aki)
        cls.paths = dict(ca=cls.ca.cert, server_crt=cls.ca.server[0], server_key=cls.ca.server[1])
        cls.CONFIG = None if cls.BODY is None else cls.BODY % cls.paths
        try:
            super().setUpClass()
        except Exception:
            cls.ca.remove()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            if not cls._failed:
                cls.ca.remove()

    def context(self, client=None, **kw):
        return self.ca.context(self.certs[client] if client else None, **kw)

    def connect_tls(self, client="certnas", listener="tls", **kw):
        kw.setdefault("server_hostname", "localhost")
        kw.setdefault("timeout", 10.0)
        return self.connect(listener=listener, tls=self.context(client), **kw)

    def assertRefused(self, connect, login=lambda c: c.pap("alice", "alicepw")):
        """The handshake or the first request fails; how depends on when the daemon gives up.

        A TLS 1.3 server checks the client certificate after the client's
        handshake already finished, so the refusal may show up only when
        the first request is sent or its reply read.
        """
        with self.assertRaises((tacacs.Closed, ssl.SSLError, ConnectionError)):
            login(connect())

    def device_and_transport(self, conn):
        r = conn.author("alice", ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        return dict(a.split("=", 1) for a in r.args if a.startswith("tactest-"))

    def assertDatagramsKeepTheConnection(self, body, datagrams):
        """users_inc() at "last-recently-used limit" evicts the oldest context; a dropped datagram must not."""
        d = self.start_daemon(body + "\tlast-recently-used limit = 1\n", udp=True, listen=self.LISTEN)
        for name, datagram in datagrams:
            with self.subTest(name):
                c = self.connect(daemon=d)
                c.pap("alice", "alicepw")   # the answer shows that the worker has the connection
                self.radius("radsecret", daemon=d, listener="dtls", source="127.0.0.9").send_raw(datagram)
                self.assertFalse(c.closed(timeout=2.0), "the datagram evicted the TACACS+ connection")


class TacacsOverTls(TlsTestCase):
    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + POLICY

    def test_pap_over_tls(self):
        c = self.connect_tls()
        self.assertEqual(c.sock.version(), "TLSv1.3")
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(c.pap("alice", "wrong").status_name, "FAIL")

    def test_ascii_login_over_tls(self):
        self.assertEqual(self.connect_tls().ascii_login("alice", "alicepw").statuses, ["GETPASS", "PASS"])

    def test_device_by_certificate_name(self):
        """The common name of the client certificate selects the device, not the address."""
        self.assertEqual(self.device_and_transport(self.connect_tls()),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_device_by_address_without_client_certificate(self):
        """Only where the device of the address doesn't ask for one (tls.peer.cert.validation = none)."""
        self.assertEqual(self.device_and_transport(self.connect_tls(client=None, source="127.0.0.9")),
                         {"tactest-device": "ipnas", "tactest-transport": "tls"})

    def test_no_client_certificate_is_refused_by_default(self):
        self.assertRefused(lambda: self.connect_tls(client=None))

    def test_unknown_certificate_name_falls_back_to_the_address(self):
        self.assertEqual(self.device_and_transport(self.connect_tls(client="nobody", source="127.0.0.9")),
                         {"tactest-device": "ipnas", "tactest-transport": "tls"})

    def test_untrusted_client_certificate_is_refused(self):
        other = tls.CA("other-ca")
        self.addCleanup(other.remove)
        ctx = self.ca.context(other.issue("certnas", "/CN=certnas.tactest"))
        self.assertRefused(lambda: self.connect(listener="tls", tls=ctx, server_hostname="localhost", timeout=10.0))

    def test_tls12_is_refused(self):
        """RFC 9887 requires TLS 1.3; without bug compatibility 128 a TLS 1.2 session gets no answer."""
        c = self.connect(listener="tls", tls=self.context("certnas", minimum=ssl.TLSVersion.TLSv1_2,
                                                          maximum=ssl.TLSVersion.TLSv1_2),
                         server_hostname="localhost", timeout=10.0)
        self.assertEqual(c.sock.version(), "TLSv1.2")
        self.assertRefused(lambda: c)

    def test_obfuscated_packet_over_tls_is_refused(self):
        """RFC 9887: no obfuscation over TLS; a packet without TAC_PLUS_UNENCRYPTED_FLAG gets ERROR, then the close."""
        c = self.connect_tls()
        pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                         version=tacacs.VERSION_ONE)
        c.send_raw(pkt.encode("tactest"))
        r = tacacs.AuthenReply(c.recv())
        self.assertEqual((r.status_name, r.server_msg), ("ERROR", "Peers MUST NOT use Obfuscation with TLS."), r)
        self.assertTrue(c.closed(), "the connection stays open")

    def test_plain_tacacs_on_a_tls_listener_is_refused(self):
        c = self.connect(listener="tls", timeout=2.0)
        with self.assertRaises((tacacs.Closed, TimeoutError)):
            c.pap("alice", "alicepw")

    def test_plain_listener_still_plain(self):
        self.assertEqual(self.device_and_transport(self.connect()),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})


class PeerCertSan(TlsTestCase):
    """The subjectAltNames of a client certificate select the device; a DNS name in there crashed the worker.

    accept_control_tls() keeps the DNS names of the certificate in an
    array of pointers, but allocated it with one byte per name: the first
    DNS name looked at wrote 8 bytes into a 2-byte block. On musl (Alpine)
    the worker died with SIGSEGV when that memory was freed, on glibc the
    heap was quietly damaged; AddressSanitizer reports it at once. Found
    with Cisco IOS-XR and a certificate from an EST server: DNS name
    first, then the IP address of the device. An IP address SAN that
    comes first selects the device before any DNS name is looked at, so
    the order matters.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + """
	device xr {
		address = 127.0.0.65
		key = xrkey
	}
	device dnsnas.tactest {
	}
""" + policy(("xr", "dnsnas.tactest", "localhost"))
    CLIENTS = {
        # the shape from the field: CN first, then serialNumber; DNS name, then the address
        "dns_then_ip": ("/CN=xr.tactest.invalid/serialNumber=e3d752c5",
                        "DNS:xr.tactest.invalid, IP:127.0.0.65"),
        "dns_names": ("/CN=other.tactest.invalid", "DNS:a.tactest.invalid, DNS:b.tactest.invalid, "
                      "DNS:c.tactest.invalid, DNS:d.tactest.invalid, DNS:dnsnas.tactest"),
        "ip_then_dns": ("/CN=xr.tactest.invalid", "IP:127.0.0.65, DNS:xr.tactest.invalid"),
        "ip_twice": ("/serialNumber=e3d752c5/CN=xr.tactest.invalid", "IP:127.0.0.65, IP:127.0.0.65"),
    }

    def device(self, client, source="127.0.0.65", single_connect=False):
        c = self.connect_tls(client, source=source, single_connect=single_connect)
        self.assertTrue(c.pap("alice", "alicepw").ok)
        return self.device_and_transport(c)["tactest-device"]

    def test_dns_san_before_ip_san(self):
        self.assertEqual(self.device("dns_then_ip"), "xr")

    def test_dns_san_before_ip_san_single_connection(self):
        self.assertEqual(self.device("dns_then_ip", single_connect=True), "xr")

    def test_dns_san_before_ip_san_from_another_address(self):
        """The address SAN selects the device, wherever the connection comes from."""
        self.assertEqual(self.device("dns_then_ip", source="127.0.0.9"), "xr")

    def test_several_dns_sans(self):
        self.assertEqual(self.device("dns_names", source="127.0.0.9"), "dnsnas")

    def test_ip_san_before_dns_san(self):
        self.assertEqual(self.device("ip_then_dns"), "xr")

    def test_ip_san_twice(self):
        self.assertEqual(self.device("ip_twice"), "xr")


class AutoDetect(TlsTestCase):
    """#236: "tls auto-detect = yes" in the realm made the daemon expect TLS only where spawnd said "tls = yes".

    With auto-detection, TLS and plain TACACS+ share a port: the first
    bytes of a connection decide. Before 238653a a TLS session on a plain
    listener was dropped after the handshake ("rejected [tac_read]"); with
    238653a alone plain sessions broke instead (fixed in 0a1e650).
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + "\ttls auto-detect = yes\n" + POLICY

    def test_issue236_tls_on_a_listener_without_tls(self):
        self.assertEqual(self.device_and_transport(self.connect_tls(listener=None)),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_issue236_plain_on_a_listener_without_tls(self):
        self.assertEqual(self.device_and_transport(self.connect()),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})

    def test_issue236_both_on_a_tls_listener(self):
        """With "tls = yes" on the listener, auto-detection is the fallback to plain TACACS+."""
        self.assertEqual(self.device_and_transport(self.connect_tls()),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})
        self.assertEqual(self.device_and_transport(self.connect(listener="tls")),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})


class ListenerTlsAuto(TlsTestCase):
    """#236, second part: "tls = auto" on a spawnd listener (0a1e650) auto-detects on that listener only."""

    LISTEN = {"auto": "tls = auto"}
    BODY = TLS_REALM + POLICY

    def test_issue236_tls_auto_listener_takes_tls(self):
        self.assertEqual(self.device_and_transport(self.connect_tls(listener="auto")),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_issue236_tls_auto_listener_takes_plain(self):
        self.assertEqual(self.device_and_transport(self.connect(listener="auto")),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})

    def test_plain_listener_does_not_auto_detect(self):
        self.assertRefused(lambda: self.connect_tls(listener=None))


REJECT_LOG_FIELDS = ("version", "error_code", "error", "verify_code", "verify", "hint")

REJECT_LOG = """
	log connection {
		destination = "$tmp/connection.log"
		connection format = "$${msgid}$${FS}$${tls.conn.version}$${FS}$${tls.conn.error.code}$${FS}$${tls.conn.error}$${FS}$${tls.peer.cert.verify.code}$${FS}$${tls.peer.cert.verify}$${FS}$${hint}"
	}
	connection log = connection
"""


PROTOCOL_LOG = """
	log connection {
		destination = "$tmp/connection.log"
		connection format = "$${msgid}$${FS}$${realm}$${FS}$${hint}"
	}
	connection log = connection
"""


class AaaProtocolAllowedTls(TlsTestCase):
    """aaa.protocol.allowed and TLS: tacacs.tls and tacacs.tcp are two protocols (#339, #342).

    A realm for TACACS+ over TLS only (RFC 9887) refuses plain TACACS+,
    also on a listener without TLS; a realm for plain TACACS+ refuses a
    TLS client. The connection log gives the refused protocol as the hint
    of the CONN-REJECT record.
    """

    LISTEN = {
        "tls-only": "tls = yes realm = tls-only",
        "tls-only-plain": "realm = tls-only",
        "tcp-only": "realm = tcp-only",
        "tcp-only-tls": "tls = yes realm = tcp-only",
    }
    BODY = TLS_REALM + PROTOCOL_LOG + POLICY + """
	realm tls-only { aaa.protocol.allowed = tacacs.tls }
	realm tcp-only { aaa.protocol.allowed = tacacs.tcp }
"""

    def assert_reject_logged(self, realm, protocol):
        self.wait_log("connection", "CONN-REJECT\t%s\t%s not in aaa.protocol.allowed\n" % (realm, protocol))

    def test_tls_only_realm(self):
        self.assertTrue(self.connect_tls(listener="tls-only").pap("alice", "alicepw").ok)
        c = self.connect(listener="tls-only-plain", timeout=10.0)
        c.send(tacacs.Packet.authen_start(user="alice"))
        self.assertTrue(c.closed())
        self.assert_reject_logged("tls-only", "tacacs.tcp")

    def test_tcp_only_realm(self):
        self.assertTrue(self.connect(listener="tcp-only").pap("alice", "alicepw").ok)
        self.assertRefused(lambda: self.connect_tls(listener="tcp-only-tls"))
        self.assert_reject_logged("tcp-only", "tacacs.tls")


def tls11_client_hello():
    """A ClientHello of a client that speaks TLS 1.1 at most (no supported_versions extension)."""
    body = b"\x03\x02" + os.urandom(32) + b"\x00" + b"\x00\x04\xc0\x13\x00\x2f" + b"\x01\x00"
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class TlsRejectReason(TlsTestCase):
    """A failed TLS handshake: the connection log says why.

    The syslog line of the reject carried the OpenSSL error ("rejected
    (error:0A000418:SSL routines::tlsv1 alert unknown ca)"), but the
    CONN-REJECT record of the connection log got nothing of it:
    accept_control_tls() handed the error text to reject_conn() for
    syslog only, and ${hint}, documented as the error message for TLS
    failures, stayed empty. ${tls.conn.error} and ${tls.conn.error.code}
    give the OpenSSL error, ${tls.peer.cert.verify} and
    ${tls.peer.cert.verify.code} the result of the client certificate
    verification. The daemon is started in every test, as the format
    uses variables an older daemon rejects.
    """

    BODY = None
    CLIENTS = {"certnas": "/CN=certnas.tactest"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.other = tls.CA(cls.__name__ + "-other")
        cls.certs["untrusted"] = cls.other.issue("untrusted", "/CN=certnas.tactest")
        cls.certs["expired"] = cls.ca.issue("expired", "/CN=certnas.tactest", expired=True)

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            if not cls._failed:
                cls.other.remove()

    def record(self, client, msgid="CONN-REJECT"):
        """Run client(daemon) against a daemon of this test; the fields of the first msgid record."""
        d = self.start_daemon(TLS_REALM % self.paths + REJECT_LOG + POLICY, listen={"tls": "tls = yes"})
        try:
            client(d)
        except (OSError, ssl.SSLError, tacacs.Closed):
            pass
        for line in d.wait_log("connection", msgid + "\t").splitlines():
            fields = line.split("\t")
            if fields[0].endswith(" " + msgid):
                return dict(zip(REJECT_LOG_FIELDS, fields[1:]))

    def tls_client(self, ctx):
        def client(d):
            c = self.connect(daemon=d, listener="tls", tls=ctx, server_hostname="localhost", timeout=10.0)
            c.pap("alice", "alicepw")   # TLS 1.3: a refused client certificate shows up after the handshake
        return client

    def raw_client(self, data):
        def client(d):
            with socket.create_connection((d.address, d.ports["tls"]), timeout=5) as s:
                if data:
                    s.sendall(data)
                    s.settimeout(2)
                    try:
                        while s.recv(4096):
                            pass
                    except OSError:
                        pass
        return client

    def assertRejected(self, r, code, error, verify_code="", verify=""):
        self.assertIsNotNone(r, "no CONN-REJECT record")
        self.assertEqual((r["error_code"], r["error"], r["verify_code"], r["verify"]), (code, error, verify_code, verify))
        self.assertEqual(r["hint"], "error:%s:SSL routines::%s" % (code, error))

    def test_client_does_not_trust_the_server(self):
        """The case from the field: the device has the wrong CA and aborts with an alert."""
        r = self.record(self.tls_client(self.other.context(self.certs["certnas"])))
        self.assertRejected(r, "0A000418", "tlsv1 alert unknown ca")
        self.assertEqual(r["version"], "TLSv1.3")

    def test_client_certificate_from_an_unknown_ca(self):
        r = self.record(self.tls_client(self.context("untrusted")))
        self.assertRejected(r, "0A000086", "certificate verify failed", "20", "unable to get local issuer certificate")

    def test_expired_client_certificate(self):
        r = self.record(self.tls_client(self.context("expired")))
        self.assertRejected(r, "0A000086", "certificate verify failed", "10", "certificate has expired")

    def test_no_client_certificate(self):
        """The handshake succeeds, the daemon refuses afterwards: no OpenSSL error, the reason is in ${hint}."""
        r = self.record(self.tls_client(self.context()))
        self.assertEqual(r, dict(version="TLSv1.3", error_code="", error="", verify_code="", verify="", hint="no cert"))

    def test_tcp_close_without_handshake(self):
        self.assertRejected(self.record(self.raw_client(b"")), "0A000126", "unexpected eof while reading")

    def test_not_tls(self):
        self.assertRejected(self.record(self.raw_client(b"GET / HTTP/1.0\r\n\r\n")), "0A00009C", "http request")

    def test_tls11_only_client(self):
        r = self.record(self.raw_client(tls11_client_hello()))
        self.assertRejected(r, "0A000102", "unsupported protocol")
        self.assertEqual(r["version"], "TLSv1.1")

    def test_accepted_connection_has_no_error(self):
        r = self.record(self.tls_client(self.context("certnas")), "CONN-START")
        self.assertEqual(r, dict(version="TLSv1.3", error_code="", error="", verify_code="", verify="", hint=""))


PSK_KEY = "0123456789abcdef0123456789abcdef"

PSK = """
	tls psk = yes
	tls cipher-suites = TLS_AES_128_GCM_SHA256
	device psknas {
		tls psk id = psknas
		tls psk key = hex %s
	}
	device pskclear {
		tls psk id = pskclear
		tls psk key = clear demoDemo
	}
	device psk6 {
		tls psk id = psk6
		tls psk key = 6 'ZKAb`S]hPDBAbXWZNJQ_BecWeZIMFYAAB' # demoDemo
	}
	type6-key = demo
""" % PSK_KEY


class Psk(TlsTestCase):
    """TLS 1.3 with a pre-shared key, through "openssl s_client -psk".

    The PSK identity is the device name here. An identity that names no
    device ("tls psk id = nas1@lab" on a device of another name) makes the
    worker use an uninitialized pointer (by_address in accept_control_tls(),
    #278), so these tests don't go there.
    """

    LISTEN = {"psk": "tls = yes tls psk = yes"}
    BODY = PSK + policy(("psknas", "pskclear", "localhost"))
    CLIENTS = {}

    def connect_psk(self, identity="psknas", key=PSK_KEY, timeout=10.0):
        sock = tls.PskSocket((self.daemon.address, self.daemon.ports["psk"]), identity, key, timeout=timeout)
        return self.connect(sock=sock, timeout=timeout)

    def test_pap_over_psk(self):
        c = self.connect_psk()
        self.assertTrue(c.pap("alice", "alicepw").ok)
        r = c.author("alice", ["service=shell", "cmd="])
        self.assertIn("tactest-transport=tls", r.args)

    def test_psk_identity_selects_the_device(self):
        r = self.connect_psk().author("alice", ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        self.assertIn("tactest-device=psknas", r.args)

    def test_clear_text_psk(self):
        self.assertTrue(self.connect_psk("pskclear", b"demoDemo".hex()).pap("alice", "alicepw").ok)

    def test_type6_psk(self):
        self.assertTrue(self.connect_psk("psk6", b"demoDemo".hex()).pap("alice", "alicepw").ok)

    def test_type6_psk_encrypted_text_is_refused(self):
        self.assertRefused(lambda: self.connect_psk("psk6", b"ZKAb`S]hPDBAbXWZNJQ_BecWeZIMFYAAB".hex()))

    def test_wrong_psk_is_refused(self):
        self.assertRefused(lambda: self.connect_psk(key="00" * 16))

    def test_unknown_identity_is_refused(self):
        self.assertRefused(lambda: self.connect_psk(identity="nosuchnas"))



RADSEC = """
	include = "%s"
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile radius {
		script {
			if (aaa.protocol == radius) {
				if (device.name == certnas.tactest) set radius[Reply-Message] = "certnas"
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = radius permit } }
	}
""" % os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")


class RadiusOverTls(TlsTestCase):
    """RADIUS over TLS (RFC 6614) on a TLS listener: the daemon tells it from TACACS+ by the first bytes."""

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + DEVICES + RADSEC

    def radsec(self, client="certnas"):
        return self.radius("radsec", listener="tls", tls=self.context(client))

    def test_access_accept(self):
        r = self.radsec().access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"certnas"], "device not selected by the certificate")
        self.assertTrue(r.message_authenticator, "no valid Message-Authenticator in the reply")

    def test_access_reject(self):
        self.assertEqual(self.radsec().access_request("alice", "wrong").code_name, "Access-Reject")

    def test_issue281_no_message_authenticator_needed_over_tls(self):
        """#281 (3): over TLS a request without Message-Authenticator is answered (bug compatibility 32 not set)."""
        self.assertNotIn("bug compatibility", self.BODY)
        r = self.radsec().access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_wrong_shared_secret_gets_no_accept(self):
        """Over TLS the shared secret is "radsec"; a request under another one is not accepted."""
        c = self.radius("not-radsec", listener="tls", tls=self.context("certnas"), timeout=2.0)
        req = radius.Packet(radius.ACCESS_REQUEST)
        password = radius.encrypt_password("alicepw", "not-radsec", req.authenticator)
        req.attributes = [(radius.USER_NAME, b"alice"), (radius.USER_PASSWORD, password)]
        c.send_raw(req.encode("not-radsec", message_authenticator=True))
        try:
            r = radius.Packet.decode(c.recv_raw())
        except (TimeoutError, ConnectionError, ssl.SSLError):
            return
        self.assertNotEqual(r.code_name, "Access-Accept", r)


class ListenerAaaProtocol(TlsTestCase):
    """aaa.protocol on a TLS listener: TACACS+ over TLS and RADIUS over TLS each get their own listener."""

    LISTEN = {"tacacs-tls": "tls = yes aaa.protocol = tacacs.tls", "radius-tls": "tls = yes aaa.protocol = radius.tls"}
    BODY = TLS_REALM + DEVICES + RADSEC

    def radsec(self, listener):
        return self.radius("radsec", listener=listener, tls=self.context("certnas"), timeout=2.0)

    def test_tacacs_tls(self):
        self.assertTrue(self.connect_tls(listener="tacacs-tls").pap("alice", "alicepw").ok)
        with self.assertRaises((TimeoutError, ConnectionError, ssl.SSLError)):
            self.radsec("tacacs-tls").access_request("alice", "alicepw")

    def test_radius_tls(self):
        self.assertEqual(self.radsec("radius-tls").access_request("alice", "alicepw").code_name, "Access-Accept")
        self.assertRefused(lambda: self.connect_tls(listener="radius-tls"))


CLASS = 25     # RADIUS attribute "Class"; the daemon ignores it in a request


class DatagramRelay(threading.Thread):
    """Forwards the datagrams between one client and addr, and counts those of the client with DTLS application data."""

    def __init__(self, addr):
        super().__init__(daemon=True)
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back.connect(addr)
        self.addr, self.client, self.application_data = self.front.getsockname(), None, 0
        self.sent = threading.Event()  # a datagram with application data went to addr
        self.stopping = False
        self.start()

    def run(self):
        while not self.stopping:
            for s in select.select([self.front, self.back], [], [], 0.05)[0]:
                try:
                    data, peer = s.recvfrom(65535)
                    if s is self.back:
                        if self.client:
                            self.front.sendto(data, self.client)
                        continue
                    self.client = peer
                    self.back.send(data)
                except OSError:
                    continue
                if data[:1] == b"\x17":  # the first record of the datagram is application data
                    self.application_data += 1
                    self.sent.set()

    def close(self):
        self.stopping = True
        self.join()
        self.front.close()
        self.back.close()


class RadiusOverDtls(TlsTestCase):
    """RADIUS over DTLS (RFC 7360) on a UDP listener with "tls = yes", through "openssl s_client -dtls1_2".

    The DTLS session lives in the context of the worker: every datagram of
    the client must reach that context, and every reply must leave from the
    listener address. The worker dropped the first datagram of a client
    when its bytes 2 and 3, read as a RADIUS length, were not its size, as
    in every DTLS record.
    """

    UDP = True
    LISTEN = {"dtls": "protocol = UDP tls = yes"}
    BODY = TLS_REALM + DEVICES.replace("key = ipkey", "key = ipkey\n\t\tradius.key = radsecret") + RADSEC

    @classmethod
    def setUpClass(cls):
        if not tls.dtls_client_available():
            raise unittest.SkipTest("openssl s_client has no DTLS")
        super().setUpClass()

    def dtls(self, client="certnas", daemon=None, **kw):
        d = daemon or self.daemon
        kw.setdefault("timeout", 10.0)
        sock = tls.DtlsSocket((d.address, d.ports["dtls"]), self.certs[client], self.ca.cert, **kw)
        return self.radius("radius/dtls", daemon=d, sock=sock, timeout=10.0)

    def test_access_accept(self):
        r = self.dtls().access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"certnas"], "device not selected by the certificate")
        self.assertTrue(r.message_authenticator, "no valid Message-Authenticator in the reply")

    def test_access_reject(self):
        self.assertEqual(self.dtls().access_request("alice", "wrong").code_name, "Access-Reject")

    def test_largest_radius_packet(self):
        """A RADIUS packet of 4096 bytes (RFC 2865 3) needs a DTLS record of more than 4096 bytes; spawnd cut it there."""
        c = self.dtls()
        req = c.pap_request("alice", "alicepw")
        remaining = 4096 - len(req.encode(c.secret))
        while remaining:
            size = min(255, remaining)
            if remaining - size == 1:
                size -= 2
            req.attributes.append((CLASS, b"x" * (size - 2)))
            remaining -= size
        self.assertEqual(len(req.encode(c.secret)), 4096)
        self.assertEqual(c.exchange(req).code_name, "Access-Accept")

    def replies(self, d, datagram, wait=1.5):
        """Send datagram to the DTLS listener from a new port; the datagrams that come back within wait seconds."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((d.address, d.ports["dtls"]))
            s.send(datagram)
            out, deadline = [], time.monotonic() + wait
            while select.select([s], [], [], max(0.0, deadline - time.monotonic()))[0]:
                out.append(s.recv(65535))
            return out

    def assertNoUser(self, d):
        deadline = time.monotonic() + 3.0
        while d.users() and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(d.users(), 0, "users of spawnd")

    @unittest.skipUnless(LINUX, "the user count of spawnd from its process title")
    def test_hello_without_the_cookie_gets_one_small_reply(self):
        """RFC 6347 4.2.1: a ClientHello without the cookie gets a HelloVerifyRequest, and nothing stays.

        The worker made a context and sent its first flight (the certificate too) to a source
        that it did not know to be real, and the context used a user slot until it timed out.
        """
        d = self.start_daemon(self.BODY % self.paths, listen=self.LISTEN)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            s.settimeout(5.0)
            client = tls.DtlsSocket(s.getsockname(), self.certs["certnas"], self.ca.cert)
            try:
                hello = s.recv(65535)  # the first ClientHello of s_client, which never gets an answer
            finally:
                client.close()
        self.assertEqual(hello[:1], b"\x16")
        out = self.replies(d, hello)
        self.assertEqual([(len(r), r[13]) for r in out], [(60, 3)], "a HelloVerifyRequest of 60 bytes, the ClientHello had %d" % len(hello))
        self.assertNoUser(d)

    @unittest.skipUnless(LINUX, "the user count of spawnd from its process title")
    def test_application_data_of_a_new_client_gets_nothing(self):
        """A new DTLS client starts with a ClientHello: a record of application data gets no context and no reply."""
        d = self.start_daemon(self.BODY % self.paths, listen=self.LISTEN)
        record = bytes([23, 0xfe, 0xfd, 0, 1]) + bytes(6) + (48).to_bytes(2, "big") + os.urandom(48)
        self.assertEqual([len(r) for r in self.replies(d, record)], [])
        self.assertNoUser(d)

    def test_plain_radius_keeps_the_least_recently_used_connection(self):
        """A DTLS listener takes no plain RADIUS: users_inc() at "last-recently-used limit" must not run for it.

        users_inc() at the limit ends the oldest context, so a plain datagram without a cookie ended a connection.
        """
        d = self.start_daemon(self.BODY % self.paths + "\tlast-recently-used limit = 1\n", listen=self.LISTEN)
        c = self.connect(daemon=d)
        c.pap("alice", "alicepw")   # the answer shows that the worker has the connection
        self.radius("radsecret", daemon=d, listener="dtls", source="127.0.0.9").send_raw(b"\x01\x00\x00\x14" + bytes(16))
        self.assertFalse(c.closed(timeout=2.0), "the datagram evicted the TACACS+ connection")

    AUTO_REALM = """
	realm auto {
		tls auto-detect = yes
		device plainnas {
			address = 127.0.0.10
			radius.key = plainsecret
		}
		user alice {
			password login = clear alicepw
			password pap = login
		}
		ruleset {
			rule { script { permit } }
		}
	}
	device redirected {
		address = 127.0.0.10
		target-realm = auto
	}
"""

    def test_plain_radius_of_a_device_with_auto_detection_in_its_target_realm(self):
        """The early check of the first datagram takes the realm of the device ("target-realm"), as the context does.

        It took the realm of the listener, without auto-detection, and dropped the plain request.
        """
        d = self.start_daemon(self.BODY % self.paths + self.AUTO_REALM, listen=self.LISTEN)
        c = self.radius("plainsecret", daemon=d, listener="dtls", source="127.0.0.10", timeout=2.0)
        self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")

    def client_hello(self):
        """The first ClientHello of s_client, which never gets an answer."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            s.settimeout(5.0)
            client = tls.DtlsSocket(s.getsockname(), self.certs["certnas"], self.ca.cert)
            try:
                return s.recv(65535)
            finally:
                client.close()

    @unittest.skipUnless(LINUX, "the user count of spawnd from its process title")
    def test_plain_listener_answers_no_client_hello(self):
        """A UDP listener without DTLS and without auto-detection sends no HelloVerifyRequest and makes no context."""
        d = self.start_daemon(self.BODY % self.paths, udp=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((d.address, d.udp_port))
            s.send(self.client_hello())
            self.assertEqual(select.select([s], [], [], 1.5)[0], [], "a reply to the ClientHello")
        self.assertNoUser(d)

    @unittest.skipUnless(LINUX, "the user count of spawnd from its process title")
    def test_realm_without_dtls_answers_no_client_hello(self):
        """A DTLS listener in a realm with neither a certificate nor "tls psk" sends no HelloVerifyRequest."""
        d = self.start_daemon(DEVICES + RADSEC, listen=self.LISTEN)
        self.assertEqual(self.replies(d, self.client_hello()), [])
        self.assertNoUser(d)

    def test_requests_during_the_host_lookup(self):
        """Requests that come while MAVIS looks up the device after the handshake all get a reply.

        They wait in the read BIO, as the context does not read during the lookup. After it, the
        worker stopped when the read BIO was empty, but OpenSSL had read both datagrams of the
        client and held the second record. The requests go in two datagrams through a relay.
        """
        body = (self.BODY % self.paths).replace('welcome banner = "certnas\\n"', 'welcome banner = "certnas\\n"\n\t\tmavis backend = yes')
        self.assertIn("mavis backend", body)
        d = self.start_daemon(Stub.module(childs=(1, 1)) + body, listen=self.LISTEN)
        Stub(d).set(result={"HOST": "ACK"}, delay={"HOST": 0.5})
        relay = DatagramRelay((d.address, d.ports["dtls"]))
        self.addCleanup(relay.close)
        c = self.radius("radius/dtls", daemon=d, sock=tls.DtlsSocket(relay.addr, self.certs["certnas"], self.ca.cert), timeout=5.0)
        first, second = c.pap_request("alice", "alicepw"), c.pap_request("alice", "alicepw")
        second.identifier = (first.identifier + 1) % 256
        c.send_raw(first.encode(c.secret))  # s_client sends it after the handshake, while the lookup waits
        self.assertTrue(relay.sent.wait(5.0), "no application data from the client")
        c.send_raw(second.encode(c.secret))  # a datagram of its own: s_client read the first request alone
        for n, r in enumerate((first, second), 1):
            try:
                reply = c.reply(r)
            except TimeoutError:
                self.fail("no reply to request %d of 2 (%d datagrams of application data)" % (n, relay.application_data))
            self.assertEqual((reply.code_name, reply.get(radius.REPLY_MESSAGE)), ("Access-Accept", [b"certnas"]))
        self.assertEqual(relay.application_data, 2)
        self.assertEqual(Stub(d).count("HOST"), 1)

    def test_more_than_64_requests_during_the_host_lookup(self):
        """Main's limit of 64 queued replies does not end a UDP context, whose queue goes out at the next turn.

        The requests wait in the read BIO during the lookup; after it, the worker answers all of them in one turn.
        """
        body = (self.BODY % self.paths).replace('welcome banner = "certnas\\n"', 'welcome banner = "certnas\\n"\n\t\tmavis backend = yes')
        d = self.start_daemon(Stub.module(childs=(1, 1)) + body, listen=self.LISTEN)
        Stub(d).set(result={"HOST": "ACK"}, delay={"HOST": 3.0})
        relay = DatagramRelay((d.address, d.ports["dtls"]))
        self.addCleanup(relay.close)
        c = self.radius("radius/dtls", daemon=d, sock=tls.DtlsSocket(relay.addr, self.certs["certnas"], self.ca.cert), timeout=10.0)
        requests = []
        for i in range(70):
            r = c.pap_request("alice", "alicepw")
            r.identifier = i
            requests.append(r)
            c.send_raw(r.encode(c.secret))
            deadline = time.monotonic() + 5.0     # one record per datagram: s_client sends what one read gets
            while relay.application_data <= i and time.monotonic() < deadline:
                select.select([], [], [], 0.005)
        for r in requests:
            try:
                self.assertEqual(c.reply(r).code_name, "Access-Accept")
            except TimeoutError:
                self.fail("no reply to request %d of 70" % (r.identifier + 1))

    def test_several_requests_in_one_session(self):
        """Each request after the first is DTLS application data: only the context with the session can read it."""
        c = self.dtls()
        for password, code in (("alicepw", "Access-Accept"), ("wrong", "Access-Reject"), ("alicepw", "Access-Accept")):
            self.assertEqual(c.access_request("alice", password).code_name, code)

    def test_two_workers(self):
        """Several clients over DTLS and over plain UDP to two workers: each datagram goes to the worker of its client."""
        d = self.start_daemon(self.BODY % self.paths, listen=self.LISTEN, udp=True, spawnd="\tspawn { instances min = 2 instances max = 2 }\n")
        if LINUX:
            self.assertEqual(len(d.workers()), 2)
        sessions = [self.dtls(daemon=d) for _ in range(4)]
        plain = [self.radius("radsecret", daemon=d, source="127.0.0.9") for _ in range(4)]
        for _ in range(3):
            for c in sessions:
                self.assertEqual(c.access_request("alice", "alicepw").code_name, "Access-Accept")
            for c in plain:
                self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name,
                                 "Access-Accept")

    def test_unknown_certificate_name_falls_back_to_the_address(self):
        r = self.dtls("nobody").access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [], "a device other than localhost selected")

    def test_accounting(self):
        r = self.dtls().accounting_request([(radius.USER_NAME, b"alice"),
                                            (radius.ACCT_STATUS_TYPE, struct.pack("!I", 1))])
        self.assertEqual(r.code_name, "Accounting-Response", r)

    def test_plain_radius_on_the_dtls_listener_gets_no_answer(self):
        """The same request that the plain UDP listener accepts."""
        plain = self.radius("radsecret", source="127.0.0.9")
        self.assertEqual(plain.access_request("alice", "alicepw", message_authenticator=True).code_name,
                         "Access-Accept")
        c = self.radius("radsecret", listener="dtls", source="127.0.0.9", timeout=2.0)
        with self.assertRaises(TimeoutError):
            c.access_request("alice", "alicepw", message_authenticator=True)


class RadiusDtlsAutoDetect(RadiusOverDtls):
    """"tls = auto" on the UDP listener: DTLS and plain RADIUS on the same port."""

    LISTEN = {"dtls": "protocol = UDP tls = auto"}

    test_plain_radius_on_the_dtls_listener_gets_no_answer = None    # the port takes plain RADIUS too
    test_plain_radius_keeps_the_least_recently_used_connection = None

    @unittest.skipUnless(LINUX, "the user count of spawnd from its process title")
    def test_client_hello_of_no_dtls_version_gets_nothing(self):
        """Auto-detection takes only a handshake record of its DTLS versions: no HelloVerifyRequest for another one."""
        d = self.start_daemon(self.BODY % self.paths, listen=self.LISTEN)
        hello = bytearray(self.client_hello())
        hello[2] = 0x01     # record version {fe, 01}: no DTLS version
        self.assertEqual(self.replies(d, bytes(hello)), [])
        self.assertNoUser(d)

    def test_plain_radius_on_the_same_port(self):
        c = self.radius("radsecret", listener="dtls", source="127.0.0.9")
        self.assertEqual(c.access_request("alice", "alicepw", message_authenticator=True).code_name, "Access-Accept")

    def test_datagram_the_dtls_check_refuses_keeps_the_least_recently_used_connection(self):
        """Only a record that accept_control_check_tls() takes for DTLS skips the RADIUS length check."""
        self.assertDatagramsKeepTheConnection(self.CONFIG, (
            ("handshake of no DTLS version", b"\x16\xfe\x01" + bytes(17)),
            ("application data of no DTLS version", b"\x17\xfe\x01" + bytes(17)),
            ("shorter than the header check", b"\x16\xfe\xfd\x00\x00")))


class RadiusDtlsRealmAutoDetect(RadiusDtlsAutoDetect):
    """"tls auto-detect = yes" in the realm: a plain UDP listener takes DTLS too."""

    LISTEN = {"dtls": "protocol = UDP"}
    BODY = RadiusOverDtls.BODY + "\ttls auto-detect = yes\n"
    test_plain_listener_answers_no_client_hello = None    # auto-detection in the realm takes DTLS on any UDP listener


class RadiusDtlsListenerRealmAutoDetect(RadiusDtlsAutoDetect):
    """"tls auto-detect = yes" in the realm also on a "tls = yes" UDP listener: plain RADIUS works there too."""

    LISTEN = {"dtls": "protocol = UDP tls = yes"}
    BODY = RadiusOverDtls.BODY + "\ttls auto-detect = yes\n"
    test_plain_listener_answers_no_client_hello = None    # auto-detection in the realm takes DTLS on any UDP listener


class RadiusDtlsRealmAutoDetectOff(RadiusOverDtls):
    """"tls auto-detect = no" in the realm on a "tls = auto" UDP listener: the listener takes DTLS only."""

    LISTEN = {"dtls": "protocol = UDP tls = auto"}
    BODY = RadiusOverDtls.BODY + "\ttls auto-detect = no\n"


class RadiusOverDtlsPsk(TlsTestCase):
    """DTLS 1.2 with a pre-shared key in a realm without a certificate, through "openssl s_client -psk"."""

    UDP = True
    LISTEN = {"dtls": "protocol = UDP tls = yes tls psk = yes", "auto": "protocol = UDP tls = auto tls psk = yes"}
    CIPHER = "PSK-AES128-GCM-SHA256"
    BODY = PSK + DEVICES + RADSEC + '\ttls ciphers = "%s"\n' % CIPHER
    CLIENTS = {}

    @classmethod
    def setUpClass(cls):
        if not tls.dtls_client_available():
            raise unittest.SkipTest("openssl s_client has no DTLS")
        super().setUpClass()

    def test_access_accept(self):
        for listener in ("dtls", "auto"):
            with self.subTest(listener=listener):
                sock = tls.SClientSocket((self.daemon.address, self.daemon.ports[listener]),
                                         ["-dtls1_2", "-timeout", "-psk_identity", "psknas", "-psk", PSK_KEY,
                                          "-cipher", self.CIPHER], timeout=10.0)
                c = self.radius("radius/dtls", listener=listener, sock=sock, timeout=10.0)
                self.assertEqual(c.access_request("alice", "alicepw").code_name, "Access-Accept")


class DtlsAutoDetectWithoutContext(TlsTestCase):
    """"tls = auto" in a realm without a certificate or a PSK: the worker cannot take DTLS."""

    UDP = True
    LISTEN = {"dtls": "protocol = UDP tls = auto"}
    BODY = None

    def test_dtls_record_keeps_the_least_recently_used_connection(self):
        self.assertDatagramsKeepTheConnection(DEVICES + RADSEC, (("ClientHello record", b"\x16\xfe\xfd" + bytes(17)),))


class PskRealmWithoutCertificate(TlsTestCase):
    """"tls psk = yes" and no certificate: a handshake without a PSK has no SSL context and is refused."""

    UDP = True
    LISTEN = {"tls": "tls = yes", "dtls": "protocol = UDP tls = yes"}
    BODY = PSK + DEVICES + RADSEC
    CLIENTS = {}

    def test_tls_without_psk_is_refused(self):
        self.assertRefused(lambda: self.connect_tls(client=None))

    def test_dtls_without_psk_is_refused(self):
        c = self.radius("radius/dtls", listener="dtls", timeout=2.0)
        c.send_raw(b"\x16\xfe\xfd" + bytes(10))
        with self.assertRaises(TimeoutError):
            c.recv_raw()


@unittest.skipUnless(LINUX, "CPU time from /proc")
class PeerCloses(TlsTestCase):
    """PR 201, 203, 204: a connection the peer closed in the middle of a packet kept the worker busy.

    recv_inject() took the 0 of recv() at EOF for data, so the worker read
    the closed socket again and again (CPU, CLOSE_WAIT). Rewritten in
    9f1167f/866f730 instead of the PRs. For every transport: send a part
    of a packet, close, and the worker must stay idle; the socket check
    after the test sees whether it closed its end.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + DEVICES.replace("key = ipkey", "key = ipkey\n\t\tradius.key = radsecret") + RADSEC

    def idle_after(self, close):
        (worker,) = self.daemon.workers()
        close()
        time.sleep(0.2)
        before = cpu_seconds(worker)
        time.sleep(1.5)
        self.assertLess(cpu_seconds(worker) - before, 0.5, "the worker is busy after the peer closed")

    def half(self, data):
        return data[:len(data) // 2]

    def test_peer_closes_plain_tacacs(self):
        c = self.connect()
        c.send_raw(self.half(tacacs.Packet.authen_start(user="alice").encode("tactest")))
        self.idle_after(c.close)

    def test_peer_closes_during_the_tls_handshake(self):
        s = socket.create_connection((self.daemon.address, self.daemon.ports["tls"]), timeout=5)
        self.addCleanup(s.close)
        # the beginning of a TLS record with a ClientHello
        s.sendall(bytes([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03]))
        self.idle_after(s.close)

    def test_peer_closes_tacacs_over_tls(self):
        c = self.connect_tls()
        c.send_raw(self.half(tacacs.Packet.authen_start(user="alice").encode("")))
        self.idle_after(c.close)

    def test_peer_closes_radius_over_tls(self):
        c = self.radius("radsec", listener="tls", tls=self.context("certnas"))
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
        c.send_raw(self.half(req.encode("radsec", message_authenticator=True)))
        self.idle_after(c.close)

    def test_peer_closes_radius_over_tcp(self):
        c = self.radius("radsecret", tcp=True, source="127.0.0.9")
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
        c.send_raw(self.half(req.encode("radsecret", message_authenticator=True)))
        self.idle_after(c.close)


class PeerCertSanValidation(TlsTestCase):
    """tls.peer.cert.san.validation = yes: an IP address SAN selects a device only if it is the peer's address.

    The address SAN was compared with the peer address over its own
    length, 4 bytes for IPv4, but both are kept as IPv4-mapped IPv6
    addresses, whose first 4 bytes are zero: every IPv4 SAN passed, and a
    certificate naming another device's address selected that device.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + """
	device checked {
		address = 127.0.0.9
		key = checkedkey
		tls.peer.cert.san.validation = yes
	}
	device xr {
		address = 127.0.0.65
		key = xrkey
	}
""" + policy(("checked", "xr", "localhost"))
    CLIENTS = {
        "xr_address": ("/CN=nothing.tactest.invalid", "IP:127.0.0.65"),
        "own_address": ("/CN=nothing.tactest.invalid", "IP:127.0.0.9"),
    }

    def device(self, client, source):
        return self.device_and_transport(self.connect_tls(client, source=source))["tactest-device"]

    def test_ip_san_of_another_device_is_ignored(self):
        self.assertEqual(self.device("xr_address", "127.0.0.9"), "checked")

    def test_ip_san_of_the_peer_is_used(self):
        self.assertEqual(self.device("own_address", "127.0.0.9"), "checked")

    def test_without_validation_the_ip_san_selects_the_device(self):
        """localhost (127.0.0.0/8) doesn't validate: the SAN wins over the address."""
        self.assertEqual(self.device("xr_address", "127.0.0.10"), "xr")


class PipeLogAfterReject(TlsTestCase):
    """#299: after a refused TLS handshake, a pipe log destination of the worker got no more records.

    The CONN-REJECT record queues the pipe for writing after the client
    socket, then the socket is closed. epoll_io_close() dropped the last
    entry of the pending change list instead of the socket's: the pipe was
    never armed for writing again, and every later record stayed in its
    buffer. A file destination doesn't go through that list.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + """
	log connpipe { destination = "|exec cat >> '$tmp/connpipe.log'" }
	connection log = connpipe
""" + POLICY

    def test_issue299_pipe_log_after_a_refused_handshake(self):
        other = tls.CA("other-ca")
        self.addCleanup(other.remove)
        with self.assertRaises(ssl.SSLError):
            self.connect(listener="tls", tls=other.context(), server_hostname="localhost", timeout=10.0)
        c = self.connect()
        port = c.sock.getsockname()[1]
        self.assertTrue(c.pap("alice", "alicepw").ok)
        c.close()
        text = self.wait_log("connpipe", "stop\ttcp\t127.0.0.1\t%d\t" % port)
        self.assertIn("reject\ttcp\t127.0.0.1\t", text)


class AkiWithoutKeyIdentifier(TlsTestCase):
    """A client certificate whose AuthorityKeyIdentifier has no keyIdentifier crashed the worker.

    accept_control_tls() reads aki->keyid without a NULL check. An
    AuthorityKeyIdentifier that carries only authorityCertIssuer and
    authorityCertSerialNumber (OpenSSL "authorityKeyIdentifier =
    issuer:always") leaves keyid NULL: the daemon dereferences it first
    when it records ${tls.peer.cert.aki}, and again, when "tls crl-dir"
    is set, while it builds the <crl-dir>/<AKI>/<serial> revocation path.
    A realm that trusts a CA it does not control and has crl-dir
    configured is hit by any peer certificate issued that way. A
    certificate with no AKI at all was already handled -- the revocation
    path falls back to an MD5 of the issuer DN -- and is kept here so
    that path stays covered.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + '\ttls crl-dir = "$tmp/crl"\n' + POLICY
    CLIENTS = {
        "keyid": "/CN=certnas.tactest",                              # a keyIdentifier (the working case)
        "issuer_serial": ("/CN=certnas.tactest", None, "issuer:always"),  # issuer + serial, keyid NULL
        "no_aki": ("/CN=certnas.tactest", None, None),              # no AuthorityKeyIdentifier at all
    }

    def selected(self, client):
        return self.device_and_transport(self.connect_tls(client=client))

    def test_aki_with_issuer_and_serial_only(self):
        """keyid NULL: the worker dereferenced it; the certificate must now be served normally."""
        self.assertEqual(self.selected("issuer_serial"), {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_no_authority_key_identifier(self):
        """No AKI: the revocation path uses the MD5 of the issuer DN; this always worked."""
        self.assertEqual(self.selected("no_aki"), {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_key_identifier_still_works(self):
        self.assertEqual(self.selected("keyid"), {"tactest-device": "certnas", "tactest-transport": "tls"})


class CrlDirPathBuffer(TlsTestCase):
    """With "tls crl-dir" the <crl-dir>/<AKI>/<serial> path is built per handshake; its buffers are too small on OpenSSL >= 4.1.

    accept_control_tls() sizes the AuthorityKeyIdentifier and serial
    parts of the path for the raw byte lengths on OpenSSL >= 4.1
    (aki_len = length + 2, serial_len = length) but then writes them as
    hex, which is twice as long. A 20-byte keyIdentifier writes 40
    characters into a 23-byte stack buffer (aki_txt), and the serial
    overruns crlfile the same way. AddressSanitizer reports the overflow
    of aki_txt at the first TLS handshake; without a sanitizer the stack
    or the resulting path is corrupted. The OpenSSL < 4.1 branch sizes
    both parts *2 and is correct, so a build against OpenSSL 3.x is not
    affected -- this test needs a daemon built against OpenSSL >= 4.1 to
    turn red.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + '\ttls crl-dir = "$tmp/crl"\n' + POLICY

    def test_crl_dir_handshake_does_not_overflow(self):
        c = self.connect_tls()
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(self.device_and_transport(c),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})
