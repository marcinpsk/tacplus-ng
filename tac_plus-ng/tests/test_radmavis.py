"""radmavis-mt and radmavis: daemon A authenticates through external-mt or external against daemon B.

B is a tac_plus-ng that answers RADIUS over UDP, RADIUS/TCP or RADIUS over
TLS. The backend sends an Access-Request with PAP to B and maps the Class
attribute of the Access-Accept to TACMEMBER ("group_attribute=Class").
For the answers B does not give
-- none at all, an Access-Challenge -- a RADIUS responder of the test
takes the place of B. All tests run with radmavis (one request at a
time, module "external") as well.

A backend error opens the fallback of the realm ("authentication
fallback period"): the fallback-only user rescue can log in. As
"authentication fallback = permit" turns an error into a deny for the
user under test, rescue is what tells a failed login from a backend
error.
"""

import hashlib
import os
import re
import select
import socket
import string
import subprocess
import threading
import unittest

from tactest import SOURCE, DaemonTestCase, features, prefix, radius, tls
from tactest.daemon import sanitizer_env

RADMAVIS_MT = os.path.join(prefix(), "sbin", "radmavis-mt")
RADMAVIS = os.path.join(prefix(), "sbin", "radmavis")
DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"
RADCLI_DICTIONARY = "/etc/radcli/dictionary"
ACCESS_CHALLENGE = 11
STATE = 24

# radcli 1.2 and 1.3 send no Message-Authenticator: B must not require it (bug compatibility 32)
SERVER = string.Template("""
	include = "$dictionary"
	device nas {
		address = $nas
		radius.key = $secret
		bug compatibility = 32
	}
	user alice { password login = clear alicepw }
	user bob { password login = clear bobpw }
	user carol { password login = clear carolpw }
	user erin { password login = clear push }
	profile reply {
		script {
			if (user == carol) permit
			if (user == alice) set radius[Class] = "netadmins"
			if (user == erin) set radius[Class] = "netadmins"
			set radius[Reply-Message] = "welcome"
			permit
		}
	}
	ruleset {
		rule { script { profile = reply permit } }
	}
""").substitute(dictionary=DICTIONARY, nas=NAS, secret=SECRET)

# RADIUS over TLS (RFC 6614): the certificate selects the device of B, and the shared secret is "radsec"
SERVER_TLS = """
	tls cert-file = "{server_crt}"
	tls key-file = "{server_key}"
	tls ca-file = "{ca}"
	device certnas.tactest {{ }}
"""

RADIUSCLIENT_CONF = """\
nas-identifier tactest
authserver {server}
acctserver {server}
bindaddr {nas}
dictionary {dictionary}
seqfile {seqfile}
mapfile /dev/null
auth_order radius
login_tries 1
radius_timeout 1
radius_retries 1
serv-type {transport}
"""

# rc_send_server() takes the secret from authserver or the servers file, then uses "radsec" over TLS
RADIUSCLIENT_TLS = """\
servers {servers}
tls-ca-file {ca}
tls-cert-file {cert}
tls-key-file {key}
"""

NETADMINS_MOTD = "Member of netadmins.\n"

# "mavis module = external-mt { exec = ... }" with radmavis-mt, or "external" with radmavis
MODULE = string.Template("""
	mavis module = $module {
		exec = "$path" "$name" "-c" "$conf" $args
	}
""")

CLIENT = string.Template("""$module
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	authentication fallback = permit
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	group netadmins { }
	ruleset {
		rule netadmins {
			script { if (member == netadmins) { motd banner = "Member of netadmins.\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")

# the first factor is local, the second (TACTYPE MFA) goes to the backend
MFA_CLIENT = string.Template("""$module
	authentication fallback = permit
	user alice {
		password login = clear alicepw
		mfa = yes
	}
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	ruleset { rule { script { permit } } }
""")

# local first factor of erin and bob; B accepts the second factor ("push") for erin only
CLIENT_MFA = string.Template("""$module
	user erin {
		password login = clear erinpw
		password pap = clear erinpw
		mfa = yes
	}
	user bob {
		password login = clear bobpw
		password pap = clear bobpw
		mfa = yes
	}
	ruleset { rule { script { permit } } }
""")


def need_tls():
    if not tls.openssl_available():
        raise unittest.SkipTest("no openssl command to make certificates")
    if "openssl" not in features():
        raise unittest.SkipTest("tac_plus-ng built without OpenSSL: B has no RADIUS over TLS")


def need_apply_config(backend):
    """Skip unless the backend applies the radcli options of the command line: radcli 1.2.10 has rc_apply_config()."""
    usage = subprocess.run([backend], capture_output=True, timeout=30, env=sanitizer_env(), check=False).stderr
    m = re.search(rb"^Version: \S+/(?:radcli (\d+)\.(\d+)\.(\d+)|freeradius-client)$", usage, re.MULTILINE)
    if m is None:
        raise AssertionError(f"no library version in the usage of {backend}: {usage!r}")
    if m[1] is None or tuple(int(n) for n in m.groups()) < (1, 2, 10):
        raise unittest.SkipTest(f"{os.path.basename(backend)} is built without rc_apply_config(): {m[0].decode()}")


def exchange(backend, conf, body, options=()):
    """One request to the backend in the legacy protocol, without tac_plus-ng."""
    return subprocess.run([backend, "-c", conf, "group_attribute=Class", *options], input=body + b"=\n",
                          capture_output=True, timeout=30, env=sanitizer_env(), check=False)


def reply_pairs(p):
    """The AV pairs of a legacy reply, {attribute number: value}; None without a result line."""
    lines = p.stdout.decode(errors="replace").splitlines()
    if not lines or not lines[-1].startswith("="):
        return None
    # radmavis adds a newline to the Reply-Message text of radcli, which ends with one already
    return dict(line.split(" ", 1) for line in lines[:-1] if line)


class Responder:
    """A RADIUS server on a free UDP port that answers every request with reply = (code, attributes).

    reply None: it never answers. requests counts what it got.
    """

    def __init__(self, reply=None):
        self.reply, self.requests = reply, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            if select.select([self.sock], [], [], 0.1)[0]:
                data, peer = self.sock.recvfrom(4096)
                request = radius.Packet.decode(data)
                self.requests += 1
                if self.reply:
                    code, attributes = self.reply
                    raw = radius.Packet(code, request.identifier, request.authenticator, attributes).encode()
                    # Response Authenticator, RFC 2865 3
                    raw = raw[:4] + hashlib.md5(raw + SECRET.encode()).digest() + raw[20:]
                    self.sock.sendto(raw, peer)

    def close(self):
        self.stop.set()
        self.thread.join()
        self.sock.close()


class RadmavisTestCase(DaemonTestCase):
    """Daemon A per test, with BACKEND in its MAVIS module."""

    CONFIG = None
    BACKEND = RADMAVIS_MT

    def tls_ca(self, name="ca"):
        need_tls()
        ca = tls.CA(self.id().split(".")[-1] + "-" + name)
        self.addCleanup(ca.remove)
        return ca

    def start_server(self, transport="udp", check=True):
        """B, the tac_plus-ng that answers RADIUS; with a TLS listener for transport "tls"."""
        body, listen = SERVER, {}
        if transport == "tls":
            self.ca = self.tls_ca()
            body = SERVER_TLS.format(ca=self.ca.cert, server_crt=self.ca.server[0], server_key=self.ca.server[1]) + body
            listen = {"tls": "tls = yes"}
        return self.start_daemon(body, udp=True, listen=listen, name=self.id().split(".")[-1] + "-server",
                                 check=check)

    def radcli_conf(self, port, transport="udp", dictionary=RADCLI_DICTIONARY, trust=None, serv_type=None):
        """trust: the CA whose certificates A accepts from B (radcli "tls-ca-file"), for transport "tls".

        serv_type: the "serv-type" line of the file, if it is not the transport.
        """
        text = RADIUSCLIENT_CONF.format(server=f"127.0.0.1:{port}" + ("" if transport == "tls" else ":" + SECRET),
                                        transport=serv_type or transport, nas=NAS, dictionary=dictionary,
                                        seqfile=self.scratch_file("radius.seq", ""))
        if transport == "tls":
            crt, key = self.ca.issue("certnas", "/CN=certnas.tactest")
            text += RADIUSCLIENT_TLS.format(servers=self.scratch_file("servers", "127.0.0.1 radsec\n"),
                                            ca=(trust or self.ca).cert, cert=crt, key=key)
        return self.scratch_file("radiusclient.conf", text)

    def start_client(self, port, template=CLIENT, dictionary=RADCLI_DICTIONARY, transport="udp", serv_type=None,
                     options=()):
        """Daemon A, with the backend asking the RADIUS server on port.

        options: radcli options for the command line of the backend, "option=value".
        """
        conf = self.radcli_conf(port, transport, dictionary, serv_type=serv_type)
        name = os.path.basename(self.BACKEND)
        args = (["group_attribute=Class"] if template in (CLIENT, CLIENT_MFA) else []) + list(options)
        module = MODULE.substitute(module="external-mt" if name == "radmavis-mt" else "external",
                                   path=self.BACKEND, name=name, conf=conf, args=" ".join(f'"{a}"' for a in args))
        return self.start_daemon(template.substitute(module=module))

    def start_pair(self, check_server=True, dictionary=RADCLI_DICTIONARY, transport="udp", template=CLIENT,
                   serv_type=None, options=()):
        """B first, then A with a radcli configuration that points at B over the transport of the test."""
        server = self.start_server(transport, check_server)
        port = {"udp": server.udp_port, "tcp": server.port, "tls": server.ports.get("tls")}[transport]
        return server, self.start_client(port, template=template, dictionary=dictionary, transport=transport,
                                         serv_type=serv_type, options=options)

    def responder(self, reply=None):
        r = Responder(reply)
        self.addCleanup(r.close)
        return r


class FailedLogin:
    """Answers of the RADIUS server that are a failed login, not a backend error that opens the fallback."""

    def test_mfa_timeout_is_a_failed_login(self):
        """No answer to the second factor is a push nobody approved, not a backend error: no fallback."""
        r = self.responder()
        a = self.start_client(r.port, template=MFA_CLIENT)
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.ascii_login("alice", "alicepw").status_name, "FAIL")
        self.assertGreater(r.requests, 0)
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")

    def test_access_challenge_is_a_failed_login(self):
        """The backend can't pass a challenge on: an Access-Challenge is a failed login, not a backend error."""
        r = self.responder((ACCESS_CHALLENGE, [(STATE, "otp"), (radius.REPLY_MESSAGE, "Enter OTP")]))
        a = self.start_client(r.port)
        with a.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        self.assertGreater(r.requests, 0)
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")

    def test_mfa_challenge_is_a_failed_login(self):
        """An Access-Challenge to the second factor: a failed login, not a backend error."""
        r = self.responder((ACCESS_CHALLENGE, [(STATE, "otp"), (radius.REPLY_MESSAGE, "Enter OTP")]))
        a = self.start_client(r.port, template=MFA_CLIENT)
        with a.connect() as c:
            self.assertEqual(c.ascii_login("alice", "alicepw").status_name, "FAIL")
        self.assertGreater(r.requests, 0)
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")


class RadiusTests(FailedLogin):
    """Each test starts B first, then A with a radcli configuration that points at the RADIUS port of B."""

    def test_pap(self):
        _, a = self.start_pair()
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_ascii_login(self):
        _, a = self.start_pair()
        for password, status in (("bobpw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.ascii_login("bob", password).status_name, status)

    def test_unknown_user(self):
        _, a = self.start_pair()
        with a.connect() as c:
            self.assertEqual(c.pap("mallory", "alicepw").status_name, "FAIL")

    def test_class_attribute_becomes_a_group(self):
        """The rule for members of netadmins sets the MOTD; bob gets no Class and so no MOTD."""
        _, a = self.start_pair()
        for user, password, motd in (("alice", "alicepw", NETADMINS_MOTD), ("bob", "bobpw", "")):
            with self.subTest(user=user), a.connect() as c:
                r = c.ascii_login(user, password)
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_access_accept_without_attributes(self):
        """B adds no attribute for carol, and radcli keeps no Message-Authenticator: the back-end gets no pairs.

        radcli drops the attributes that its dictionary does not have. A
        build of B without OpenSSL sends no Message-Authenticator at all.
        """
        with open(RADCLI_DICTIONARY) as f:
            lines = [line for line in f if "Message-Authenticator" not in line]
        _, a = self.start_pair(dictionary=self.scratch_file("dictionary", "".join(lines)))
        with a.connect() as c:
            self.assertEqual(c.pap("carol", "carolpw").status_name, "PASS")

    def test_pap_over_tcp(self):
        """RADIUS/TCP (RFC 6613) on the TACACS+ port of B. radcli sends no Message-Authenticator here either."""
        _, a = self.start_pair(transport="tcp")
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_pap_over_tls(self):
        """RADIUS over TLS: A checks the certificate of B against the test CA, B checks the one of A."""
        _, a = self.start_pair(transport="tls")
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_class_attribute_over_tls(self):
        _, a = self.start_pair(transport="tls")
        with a.connect() as c:
            r = c.ascii_login("alice", "alicepw")
            self.assertEqual((r.status_name, r.server_msg), ("PASS", NETADMINS_MOTD), r)

    def test_option_on_the_command_line(self):
        """The option "serv-type=tcp" on the command line overrides "serv-type udp" in the file."""
        need_apply_config(self.BACKEND)
        _, a = self.start_pair(transport="tcp", serv_type="udp", options=["serv-type=tcp"])
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_bad_option_on_the_command_line(self):
        """The backend exits when radcli cannot apply an option of the command line."""
        need_apply_config(self.BACKEND)
        conf = self.radcli_conf(self.start_server().udp_port)
        request = b"0 TACPLUS\n4 alice\n8 alicepw\n49 AUTH\n"
        p = exchange(self.BACKEND, conf, request, ["serv-type=bogus"])
        self.assertEqual((p.returncode, reply_pairs(p)), (255, None), p)
        self.assertIn(b"Applying the command line options failed.", p.stderr)

    def test_tls_option_on_the_command_line(self):
        """Over TLS the backend starts a second session for the options: "tls-ca-file" of another CA fails it."""
        need_apply_config(self.BACKEND)
        b = self.start_server("tls")
        conf = self.radcli_conf(b.ports.get("tls"), "tls")
        request = b"0 TACPLUS\n4 alice\n8 alicepw\n49 AUTH\n"
        p = exchange(self.BACKEND, conf, request, ["radius_timeout=2"])
        self.assertEqual(reply_pairs(p).get("6"), "ACK", p)
        p = exchange(self.BACKEND, conf, request, ["tls-ca-file=" + self.tls_ca("other").cert])
        self.assertEqual((p.returncode, reply_pairs(p)), (255, None), p)
        self.assertIn(b"Applying the command line options failed.", p.stderr)

    def test_tls_server_not_trusted(self):
        """radcli does the TLS handshake when it reads its configuration: without trust in B, the backend exits.

        Through A, such a login waits until A closes the connection, so the
        backend runs here without A.
        """
        b = self.start_server("tls")
        request = b"0 TACPLUS\n4 alice\n8 alicepw\n49 AUTH\n"
        port = b.ports.get("tls")
        p = exchange(self.BACKEND, self.radcli_conf(port, "tls"), request)
        self.assertEqual(reply_pairs(p).get("6"), "ACK", p)
        conf = self.radcli_conf(port, "tls", trust=self.tls_ca("other"))
        p = exchange(self.BACKEND, conf, request)
        self.assertEqual((p.returncode, reply_pairs(p)), (255, None), p)
        self.assertIn(b"Parsing %s failed." % conf.encode(), p.stderr)

    def test_server_stopped(self):
        """No answer from the RADIUS server is a backend error: the fallback-only user can log in."""
        b, a = self.start_pair(check_server=False)
        with a.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        self.assertEqual(b.stop(remove=False), [])
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")

    def test_password_timeout_is_a_backend_error(self):
        """The RADIUS server gets the Access-Request and never answers: the fallback opens."""
        r = self.responder()
        a = self.start_client(r.port)
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")
        self.assertGreater(r.requests, 0)


# a subclass inherits the skip of its TestCase base, so the two backends share only a mixin
@unittest.skipUnless(os.path.exists(RADMAVIS_MT), "the build has no radmavis-mt (radcli or pthreads missing)")
class RadiusServer(RadiusTests, RadmavisTestCase):
    """The tests with radmavis-mt, in "mavis module = external-mt"."""


@unittest.skipUnless(os.path.exists(RADMAVIS_MT), "the build has no radmavis-mt (radcli or pthreads missing)")
class RadiusMfa(RadmavisTestCase):
    """MFA: after the local password of A, radmavis-mt sends B an Access-Request with the password "push".

    B is the MFA proxy: it accepts "push" for erin (the user confirms) and
    not for bob (the user declines). radmavis sends the first factor
    again in place of "push".
    """

    def test_pap_with_the_second_factor(self):
        _, a = self.start_pair(template=CLIENT_MFA)
        for user, password, status in (("erin", "erinpw", "PASS"), ("bob", "bobpw", "FAIL")):
            with self.subTest(user=user), a.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)

    def test_ascii_login_with_the_second_factor(self):
        _, a = self.start_pair(template=CLIENT_MFA)
        for user, password, status in (("erin", "erinpw", "PASS"), ("bob", "bobpw", "FAIL")):
            with self.subTest(user=user), a.connect() as c:
                r = c.ascii_login(user, password)
                self.assertEqual(r.statuses, ["GETPASS", status], r)

    def test_mfa_reply_has_no_groups(self):
        """B sends the same Access-Accept with Class for both: only the AUTH reply has TACMEMBER.

        tac_plus-ng ignores TACMEMBER in an MFA reply, so the backend runs
        here without A. For MFA, radmavis-mt sends "push" and leaves PASSWORD
        out of the reply: the first factor does not come back.
        """
        conf = self.radcli_conf(self.start_server().udp_port)
        auth = exchange(RADMAVIS_MT, conf, b"0 TACPLUS\n4 erin\n8 push\n49 AUTH\n")
        self.assertEqual(reply_pairs(auth), {"0": "TACPLUS", "4": "erin", "8": "push", "49": "AUTH",
                                             "17": "welcome", "47": '"netadmins"', "52": "1", "36": "push",
                                             "6": "ACK"}, auth)
        mfa = exchange(RADMAVIS_MT, conf, b"0 TACPLUS\n4 erin\n8 erinpw\n49 MFA\n")
        self.assertEqual(reply_pairs(mfa), {"0": "TACPLUS", "4": "erin", "49": "MFA", "17": "welcome", "6": "ACK"},
                         mfa)


@unittest.skipUnless(os.path.exists(RADMAVIS), "the build has no radmavis (radcli missing)")
class Radmavis(RadiusTests, RadmavisTestCase):
    """The same tests with radmavis, in "mavis module = external"."""

    BACKEND = RADMAVIS


if __name__ == "__main__":
    unittest.main()
