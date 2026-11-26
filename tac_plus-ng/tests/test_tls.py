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

import hashlib
import hmac
import os
import socket
import ssl
import struct
import time
import unittest

from tactest import LINUX, SOURCE, DaemonTestCase, cpu_seconds, features, radius, tacacs, tls

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

    def relay(self, version, listener=None):
        """A tls.RecordVersionRelay to the first listener, or to ports[listener]."""
        d = self.daemon
        r = tls.RecordVersionRelay(d.addr if listener is None else (d.address, d.ports[listener]), version)
        self.addCleanup(r.close)
        return r

    def connect_tls_in_record(self, version, listener=None, client="certnas"):
        """connect_tls() with the ClientHello in a record of that version (RFC 8446 5.1 allows 0x0301 and 0x0303)."""
        sock = socket.create_connection(self.relay(version, listener).addr, timeout=10.0)
        try:
            sock = self.context(client).wrap_socket(sock, server_hostname="localhost")
        except Exception:
            sock.close()
            raise
        return self.connect(sock=sock, timeout=10.0)

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

    def test_tls12_record_version_on_a_listener_without_tls(self):
        """RFC 8446 5.1: the record of the first ClientHello may say 0x0303 (LibreSSL clients with TLS 1.2 minimum)."""
        self.assertEqual(self.device_and_transport(self.connect_tls_in_record(0x0303)),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})


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

    def test_tls_auto_listener_takes_any_record_version(self):
        """RFC 5246 E.1: accept any {03,XX} as the record version of a ClientHello; RFC 8446 5.1: ignore it."""
        for version in (0x0300, 0x0302, 0x0303, 0x0304):
            with self.subTest(version="%04x" % version):
                self.assertEqual(self.device_and_transport(self.connect_tls_in_record(version, listener="auto")),
                                 {"tactest-device": "certnas", "tactest-transport": "tls"})

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


class PskBesideCertificates(TlsTestCase):
    """TLS 1.3 PSK and certificates on one listener without "tls psk = yes": the ClientHello names the PSK identity."""

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + PSK + DEVICES + policy(("certnas.tactest", "psknas", "localhost"))

    def connect_psk(self, addr):
        # X25519 only: the daemon looks for the identity in the first 1024 bytes, and an ML-KEM key share is longer
        return self.connect(sock=tls.PskSocket(addr, "psknas", PSK_KEY, timeout=10.0, groups="X25519"), timeout=10.0)

    def test_psk(self):
        self.assertEqual(self.device_and_transport(self.connect_psk((self.daemon.address, self.daemon.ports["tls"]))),
                         {"tactest-device": "psknas", "tactest-transport": "tls"})

    def test_psk_in_a_tls12_record(self):
        """RFC 8446 5.1: the record of the first ClientHello may say 0x0303 instead of 0x0301."""
        self.assertEqual(self.device_and_transport(self.connect_psk(self.relay(0x0303, listener="tls").addr)),
                         {"tactest-device": "psknas", "tactest-transport": "tls"})

    def test_certificate(self):
        self.assertEqual(self.device_and_transport(self.connect_tls()),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})


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


class RadiusOverDtls(TlsTestCase):
    """RADIUS over DTLS (RFC 7360) on a "protocol = UDP tls = yes" listener, through "openssl s_client -dtls1_2"."""

    UDP = True
    LISTEN = {"dtls": "protocol = UDP tls = yes"}
    BODY = TLS_REALM + DEVICES.replace("key = ipkey", "key = ipkey\n\t\tradius.key = radsecret") + RADSEC

    @classmethod
    def setUpClass(cls):
        if not tls.dtls_client_available():
            raise unittest.SkipTest("openssl s_client has no DTLS")
        super().setUpClass()

    def dtls(self, client="certnas"):
        sock = tls.DtlsSocket((self.daemon.address, self.daemon.ports["dtls"]), self.ca.cert, self.certs[client],
                              timeout=10.0)
        return self.radius("radius/dtls", listener="dtls", sock=sock, timeout=10.0)

    def test_access_accept(self):
        r = self.dtls().access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"certnas"], "device not selected by the certificate")

    def test_access_reject(self):
        self.assertEqual(self.dtls().access_request("alice", "wrong").code_name, "Access-Reject")

    def test_several_requests_in_one_session(self):
        c = self.dtls()
        for password, code in (("alicepw", "Access-Accept"), ("wrong", "Access-Reject"), ("alicepw", "Access-Accept")):
            with self.subTest(password=password):
                self.assertEqual(c.access_request("alice", password).code_name, code)

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


class RadiusDtlsListenerRealmAutoDetect(RadiusDtlsAutoDetect):
    """"tls auto-detect = yes" in the realm also on a "tls = yes" UDP listener: plain RADIUS works there too."""

    LISTEN = {"dtls": "protocol = UDP tls = yes"}
    BODY = RadiusOverDtls.BODY + "\ttls auto-detect = yes\n"


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


def _hkdf_expand_label(secret, label, context, length=32):
    """RFC 8446 7.1 HKDF-Expand-Label with SHA-256, for at most one hash length."""
    full = b"tls13 " + label
    info = struct.pack("!HB", length, len(full)) + full + bytes([len(context)]) + context
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def psk_ke_client_hello(identity, key):
    """A TLS 1.3 ClientHello with an external PSK that offers only psk_ke (no (EC)DHE) and no key share.

    openssl s_client always offers psk_dhe_ke, so this one is built by
    hand; the binder follows RFC 8446 4.2.11.2 for TLS_AES_128_GCM_SHA256.
    """
    def ext(kind, data):
        return struct.pack("!HH", kind, len(data)) + data

    identities = struct.pack("!H", len(identity)) + identity + struct.pack("!I", 0)
    identities = struct.pack("!H", len(identities)) + identities
    binders_len = 2 + 1 + 32
    extensions = (ext(43, b"\x02\x03\x04")                        # supported_versions: TLS 1.3
                  + ext(13, b"\x00\x04\x04\x03\x08\x04")          # signature_algorithms
                  + ext(45, b"\x01\x00"))                         # psk_key_exchange_modes: psk_ke only
    psk_ext_len = len(identities) + binders_len
    extensions_len = len(extensions) + 4 + psk_ext_len
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + b"\x00\x02\x13\x01" + b"\x01\x00"                  # TLS_AES_128_GCM_SHA256, no compression
            + struct.pack("!H", extensions_len) + extensions
            + struct.pack("!HH", 41, psk_ext_len) + identities)  # pre_shared_key, up to the binders
    length = len(body) + binders_len
    truncated = b"\x01" + length.to_bytes(3, "big") + body
    early = hmac.new(bytes(32), key, hashlib.sha256).digest()
    binder_key = _hkdf_expand_label(early, b"ext binder", hashlib.sha256(b"").digest())
    finished_key = _hkdf_expand_label(binder_key, b"finished", b"")
    binder = hmac.new(finished_key, hashlib.sha256(truncated).digest(), hashlib.sha256).digest()
    handshake = truncated + struct.pack("!HB", 33, 32) + binder
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def server_hello_extensions(sock):
    """The extension types of the ServerHello, or None if the server answers with an alert or closes."""
    data = b""
    while len(data) < 5 or len(data) < 5 + struct.unpack("!H", data[3:5])[0]:
        try:
            chunk = sock.recv(4096)
        except (ConnectionError, socket.timeout):
            return None
        if not chunk:
            return None
        data += chunk
    if data[0] != 22 or data[5] != 2:                             # not a handshake record with a ServerHello
        return None
    p = 5 + 4 + 2 + 32
    p += 1 + data[p]                                              # legacy_session_id_echo
    p += 2 + 1                                                    # cipher_suite, legacy_compression_method
    end = p + 2 + struct.unpack("!H", data[p:p + 2])[0]
    p += 2
    found = []
    while p + 4 <= end:
        kind, size = struct.unpack("!HH", data[p:p + 4])
        found.append(kind)
        p += 4 + size
    return found


PSK_POLICY = policy(("psknas", "pskclear", "localhost"))


class PskKeyExchange(TlsTestCase):
    """A TLS 1.3 PSK session takes an (EC)DHE exchange unless "tls psk key-exchange" says otherwise.

    With psk_ke alone, the session keys come from the PSK only: whoever
    learns the PSK later decrypts every recorded session. RFC 9257 and
    the ANSSI TLS guide recommend psk_dhe_ke. The default accepted psk_ke
    as well (SSL_OP_ALLOW_NO_DHE_KEX), the same as "auto".
    """

    LISTEN = {"psk": "tls = yes tls psk = yes"}
    BODY = None
    CLIENTS = {}

    def server_extensions(self, setting=""):
        d = self.start_daemon(PSK.replace("\ttls psk = yes\n", "\ttls psk = yes\n" + setting) + PSK_POLICY,
                              listen=self.LISTEN)
        with socket.create_connection((d.address, d.ports["psk"]), timeout=10.0) as s:
            s.sendall(psk_ke_client_hello(b"psknas", bytes.fromhex(PSK_KEY)))
            return server_hello_extensions(s)

    def test_psk_ke_is_refused_by_default(self):
        self.assertIsNone(self.server_extensions())

    def test_psk_ke_is_refused_with_dhe(self):
        self.assertIsNone(self.server_extensions("\ttls psk key-exchange = dhe\n"))

    def test_psk_ke_with_auto(self):
        """The ClientHello itself is right: with "auto" the server takes the PSK without a key share."""
        found = self.server_extensions("\ttls psk key-exchange = auto\n")
        self.assertIsNotNone(found, "no ServerHello")
        self.assertIn(41, found, "the server did not take the PSK")
        self.assertNotIn(51, found, "a key share in a psk_ke session")

    def test_psk_dhe_ke_still_works(self):
        """openssl s_client offers psk_dhe_ke: the default must still let it in."""
        d = self.start_daemon(PSK + PSK_POLICY, listen=self.LISTEN)
        sock = tls.PskSocket((d.address, d.ports["psk"]), "psknas", PSK_KEY, timeout=10.0)
        self.assertTrue(self.connect(daemon=d, sock=sock, timeout=10.0).pap("alice", "alicepw").ok)
