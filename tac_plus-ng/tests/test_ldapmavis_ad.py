"""LDAP back-ends against Active Directory (a Samba AD DC): ldapmavis-mt, the Perl and the Python back-end.

samba-dc/start runs the DC in a container and prints the TACTEST_SAMBA_*
variables (see README); without TACTEST_SAMBA_DC the tests are skipped.
Each test class adds its users and groups to an OU of its own, with the
ldap-utils commands over LDAPS as the domain administrator, and removes
them at the end. So the tests can run again against the same DC. The
back-ends get no LDAP_FILTER: they must detect AD to find the users by
sAMAccountName.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import secrets
import shutil
import ssl
import string
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from typing import ClassVar
from unittest import mock

from tactest import DaemonTestCase
from tactest.tls import CA
from test_ldapmavis import (
    LDAP_PERL,
    LDAP_PYTHON,
    LDAPMAVIS,
    PERL,
    PYTHON,
    perl_ldap,
    perl_string,
    python_ldap3,
    slapd_arg,
)

URL = os.environ.get("TACTEST_SAMBA_DC")
SETTINGS = ("TACTEST_SAMBA_BASE", "TACTEST_SAMBA_ADMIN", "TACTEST_SAMBA_PASSWORD", "TACTEST_SAMBA_CA")
SKIP_REASON = "TACTEST_SAMBA_DC is unset (see samba-dc/start in README)"

SECOND = -10000000          # AD time spans: 100 ns units, negative
PASSWORD_MAX_AGE = 1        # seconds, for the users with an expired password
LOCKOUT_THRESHOLD = 2
POSIX_GID = 4711
# the domain password policy of samba-dc/entrypoint: the tests change passwords at once and repeat them
DOMAIN_POLICY = {"pwdProperties": "0", "pwdHistoryLength": "0", "minPwdLength": "1", "minPwdAge": "0",
                 "maxPwdAge": "-9223372036854775808"}

# a fine-grained password policy (PSO) for some users of the OU
PSO = string.Template("""\
dn: $dn
objectClass: msDS-PasswordSettings
msDS-PasswordSettingsPrecedence: 10
msDS-PasswordReversibleEncryptionEnabled: FALSE
msDS-PasswordHistoryLength: 0
msDS-PasswordComplexityEnabled: FALSE
msDS-MinimumPasswordLength: 1
msDS-MinimumPasswordAge: 0
msDS-MaximumPasswordAge: $max_age
msDS-LockoutThreshold: $lockout
msDS-LockoutObservationWindow: $hour
msDS-LockoutDuration: $hour
$applies""")

# the bind errors of AD for the correct password: user, data code, the text of the back-ends
BIND_ERRORS = (
    ("mustchange", "773", "User must reset password."),
    ("disabled", "533", "Account disabled."),
    ("expired", "701", "Account expired."),
    ("nohours", "530", "Not permitted to logon at this time."),
    ("elsewhere", "531", "Not permitted to logon at this workstation."),
    ("pwexpired", "532", "Password expired."),
    ("locked", "775", "User account locked."),
)


def settings():
    """The TACTEST_SAMBA_* values; with TACTEST_SAMBA_DC set, a missing one is an error."""
    missing = [k for k in SETTINGS if not os.environ.get(k)]
    if missing:
        raise AssertionError("TACTEST_SAMBA_DC is set, but not " + ", ".join(missing))
    return {k: os.environ[k] for k in SETTINGS}


def unicode_pwd(password):
    """The unicodePwd value for LDIF: the password in double quotes, UTF-16LE, base64."""
    return base64.b64encode(f'"{password}"'.encode("utf-16-le")).decode()


def ldap_tool(tool, args, stdin, ok=(0,), dn=None, password=None):
    """Run an ldap-utils command, as the domain administrator unless dn is set, with the certificate check of the DC.

    Returns the output.
    """
    s = settings()
    path = shutil.which(tool)
    if path is None:
        raise AssertionError(f"TACTEST_SAMBA_DC is set, but {tool} (ldap-utils) is missing")
    env = dict(os.environ, LDAPTLS_CACERT=s["TACTEST_SAMBA_CA"], LDAPTLS_REQCERT="demand")
    bind = [dn, password] if dn else [s["TACTEST_SAMBA_ADMIN"], s["TACTEST_SAMBA_PASSWORD"]]
    p = subprocess.run([path, "-x", "-H", URL, "-D", bind[0], "-w", bind[1], *args], input=stdin, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=60)
    if p.returncode not in ok:
        raise AssertionError(f"{tool} failed ({p.returncode}):\n{p.stdout}")
    return p.stdout


def ldap_attributes(dn, *attributes):
    """The attributes of one entry, read by ldapsearch; one value each."""
    out = ldap_tool("ldapsearch", ["-LLL", "-o", "ldif-wrap=no", "-b", dn, "-s", "base", *attributes], None)
    return dict(line.split(": ", 1) for line in out.splitlines() if ": " in line and not line.startswith("dn: "))


class Domain:
    """The users and groups of one test class, in OU=tactest-<tag>; the login name of a user is <cn>-<tag>.

    alice and grouped are members of netadmins, netadmins of staff, dave
    of staff; posix has the gidNumber of the posixGroup unix. The account
    states of the BIND_ERRORS users, of inactive (533), and of reset,
    renew, refused and grouped (773) and aged (532), give the bind errors
    of AD.
    """

    # cn: (userAccountControl, more LDIF lines); 512: a normal account, 514: disabled
    USERS: ClassVar[dict[str, tuple[int, str]]] = {
        "reader": (512, ""),
        "alice": (512, ""),
        "bob": (512, ""),
        "carol": (512, ""),
        "dave": (512, ""),
        "posix": (512, f"gidNumber: {POSIX_GID}\n"),
        "mustchange": (512, "pwdLastSet: 0\n"),
        "reset": (512, "pwdLastSet: 0\n"),
        "renew": (512, "pwdLastSet: 0\n"),
        "grouped": (512, "pwdLastSet: 0\n"),
        "refused": (512, "pwdLastSet: 0\n"),
        "disabled": (514, ""),
        "inactive": (514, ""),
        "expired": (512, "accountExpires: 1\n"),
        "nohours": (512, f"logonHours:: {base64.b64encode(bytes(21)).decode()}\n"),
        "elsewhere": (512, "userWorkstations: nowhere\n"),
        "pwexpired": (512, ""),
        "aged": (512, ""),
        "locked": (512, ""),
        "lockmsg": (512, ""),
    }

    def __init__(self):
        self.base = settings()["TACTEST_SAMBA_BASE"]
        self.tag = secrets.token_hex(3)
        self.ou = f"OU=tactest-{self.tag},{self.base}"
        self.psos = {what: f"CN=tactest-{self.tag}-{what},CN=Password Settings Container,CN=System,{self.base}"
                     for what in ("expired", "lockout")}
        self.created = None

    def login(self, cn):
        return f"{cn}-{self.tag}"

    def dn(self, cn):
        return f"CN={cn},{self.ou}"

    @staticmethod
    def password(cn):
        return cn + "-pw"

    def create(self):
        policy = ldap_attributes(self.base, *DOMAIN_POLICY)
        if policy != DOMAIN_POLICY:
            raise AssertionError(f"the DC does not have the password policy of samba-dc/entrypoint: {policy}")
        ldif = [f"dn: {self.ou}\nobjectClass: organizationalUnit\n"]
        for cn, (uac, more) in self.USERS.items():
            ldif.append(f"dn: {self.dn(cn)}\nobjectClass: user\nsAMAccountName: {self.login(cn)}\n"
                        f"unicodePwd:: {unicode_pwd(self.password(cn))}\nuserAccountControl: {uac}\n{more}")
        for cn, members in (("netadmins", ["alice", "grouped"]), ("staff", ["netadmins", "dave"])):
            ldif.append(f"dn: {self.dn(cn)}\nobjectClass: group\nsAMAccountName: {self.login(cn)}\n"
                        + "".join(f"member: {self.dn(m)}\n" for m in members))
        ldif.append(f"dn: {self.dn('unix')}\nobjectClass: group\nobjectClass: posixGroup\n"
                    f"sAMAccountName: {self.login('unix')}\ngidNumber: {POSIX_GID}\n")
        hour = 3600 * SECOND
        for what, max_age, lockout, users in (("expired", PASSWORD_MAX_AGE * SECOND, 0, ("pwexpired", "aged")),
                                              ("lockout", 1000 * hour, LOCKOUT_THRESHOLD, ("locked", "lockmsg"))):
            applies = "".join(f"msDS-PSOAppliesTo: {self.dn(u)}\n" for u in users)
            ldif.append(PSO.substitute(dn=self.psos[what], max_age=max_age, lockout=lockout, hour=hour,
                                       applies=applies))
        ldap_tool("ldapadd", [], "\n".join(ldif))
        self.created = time.monotonic()

    # 32: no such object, after a create() that stopped early
    @staticmethod
    def remove_pso(dn):
        ldap_tool("ldapdelete", [dn], None, ok=(0, 32))

    def remove_ou(self):
        ldap_tool("ldapdelete", ["-r", self.ou], None, ok=(0, 32))

    def bind_code(self, cn, password):
        """The "data" code of AD for a bind as cn, "" if the bind succeeds."""
        out = ldap_tool("ldapwhoami", [], None, ok=(0, 49), dn=self.dn(cn), password=password)
        m = re.search(r", data ([0-9a-f]+),", out)
        return m.group(1) if m else ""

    def wait_password_expired(self):
        time.sleep(max(0.0, self.created + PASSWORD_MAX_AGE + 1 - time.monotonic()))


def ber(data, i=0):
    """(tag, value, end) of the BER element at data[i]; None while it is incomplete."""
    if len(data) < i + 2:
        return None
    length, start = data[i + 1], i + 2
    if length & 0x80:
        start += length & 0x7F
        length = int.from_bytes(data[i + 2:start], "big")
    if len(data) < start + length:
        return None
    return data[i], data[start:start + length], start + length


class Relay:
    """An LDAPS relay to the DC; it records the bind, search and modify requests and the bind results of each connection.

    refuse: a DN. The relay itself answers the first bind of this DN that
    follows a failed bind on the same connection, with resultCode 49
    (invalidCredentials); the DC does not get that bind.
    """

    def __init__(self, ca, refuse=None):
        # (connection, "bind" and the DN | "bound" and the result code | "search" or "modify" and the DN)
        self.events = []
        self.count = 0
        self.refuse = refuse
        self.refused = False
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(*ca.server)
        self.dc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.dc.load_verify_locations(settings()["TACTEST_SAMBA_CA"])
        self.loop = asyncio.new_event_loop()
        self.server = self.loop.run_until_complete(asyncio.start_server(self.serve, "127.0.0.1", 0, ssl=server))
        self.url = f"ldaps://127.0.0.1:{self.server.sockets[0].getsockname()[1]}"
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    async def serve(self, client_reader, client_writer):
        self.count += 1
        conn = self.count
        dc = urllib.parse.urlsplit(URL)
        dc_reader, dc_writer = await asyncio.open_connection(dc.hostname, dc.port or 636, ssl=self.dc)
        copies = [asyncio.ensure_future(self.copy(conn, reader, writer, back))
                  for reader, writer, back in ((client_reader, dc_writer, client_writer),
                                               (dc_reader, client_writer, dc_writer))]
        await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
        for writer in (client_writer, dc_writer):
            writer.close()

    async def copy(self, conn, reader, writer, back):
        """Copy each complete LDAPMessage from reader to writer, or send the answer of the relay to back."""
        data = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            data += chunk
            while (message := ber(data)) is not None:
                end = message[2]
                answer = self.record(conn, data[:end])
                out = back if answer else writer
                out.write(answer or data[:end])
                await out.drain()
                data = data[end:]

    def record(self, conn, message):
        """Record one LDAPMessage (SEQUENCE: messageID, protocolOp); return the answer of the relay, or None."""
        _, body, _ = ber(message)
        tag, op, _ = ber(body, ber(body)[2])
        if tag == 0x60:     # BindRequest: version, name
            dn = ber(op, ber(op)[2])[1].decode()
            results = [value for c, kind, value in self.events if c == conn and kind == "bound"]
            self.events.append((conn, "bind", dn))
            if (self.refuse and not self.refused and dn.lower() == self.refuse.lower()
                    and results and results[-1] != 0):
                self.refused = True
                self.events.append((conn, "bound", 49))
                # BindResponse: resultCode 49, matchedDN and diagnosticMessage empty
                op = b"\x61\x07\x0a\x01\x31\x04\x00\x04\x00"
                msgid = body[:ber(body)[2]]
                return bytes([0x30, len(msgid) + len(op)]) + msgid + op
        elif tag == 0x61:   # BindResponse: resultCode
            self.events.append((conn, "bound", int.from_bytes(ber(op)[1], "big")))
        elif tag == 0x63:   # SearchRequest: baseObject
            self.events.append((conn, "search", ber(op)[1].decode()))
        elif tag == 0x66:   # ModifyRequest: object
            self.events.append((conn, "modify", ber(op)[1].decode()))
        return None

    async def stop(self):
        self.server.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def close(self):
        asyncio.run_coroutine_threadsafe(self.stop(), self.loop).result(60)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join()
        self.loop.close()


MODULE = string.Template("""
	mavis module = $module {
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_USER = "$reader"
		setenv LDAP_PASSWD = "$readerpw"
$env
		exec = $exec
	}
""")

POLICY = string.Template("""
$module
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	authentication fallback = permit
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	group netadmins { }
	group staff { }
	group unix { }
	ruleset {
		rule nested {
			script { if (member == netadmins && memberof == "$staff") { motd banner = "netadmins in staff\\n" permit } }
		}
		rule netadmins {
			script { if (member == netadmins) { motd banner = "netadmins only\\n" permit } }
		}
		rule staff {
			script { if (memberof == "$staff") { motd banner = "staff\\n" permit } }
		}
		rule unix {
			script { if (member == unix) { motd banner = "unix\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")


class AdTests:
    """The tests for both back-ends; a subclass sets MODULE, EXEC, MESSAGE (its bind error text) and env(ca) (TLS)."""

    # the back-end checks the certificate of the DC with the CA of env()
    CHECKS_CA = True
    # the password change of a 773 or 532 account binds as the user, then again as LDAP_USER
    CHPW_REBIND = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.domain = Domain()
        # a cleanup for each entry: unittest runs the others also when one fails
        cls.addClassCleanup(cls.domain.remove_ou)
        for dn in cls.domain.psos.values():
            cls.addClassCleanup(cls.domain.remove_pso, dn)
        cls.domain.create()

    def start(self, command=None, check=True, url=URL, ca=None, config="", **env):
        """The daemon with the back-end of the class (or command); config goes in front of the MAVIS module.

        env: more setenv lines, None unsets one.
        """
        d = self.domain
        tls = self.env(ca or settings()["TACTEST_SAMBA_CA"])
        # the daemon reads a quoted string as slapd.conf does
        lines = "\n".join(f"\t\tsetenv {k} = {slapd_arg(v)}" for k, v in {**tls, **env}.items() if v is not None)
        module = MODULE.substitute(module=self.MODULE, url=url, base=d.ou, reader=d.dn("reader"),
                                   readerpw=d.password("reader"), env=lines, exec=command or self.EXEC)
        return self.start_daemon(POLICY.substitute(module=config + module, staff=d.dn("staff")), check=check)

    def start_relay(self, refuse=None):
        """Start a Relay (refuse: see there) and the daemon with the relay as its DC; return both."""
        ca = CA("ad-relay")
        self.addCleanup(ca.remove)
        relay = Relay(ca, refuse)
        self.addCleanup(relay.close)
        return relay, self.start(url=relay.url, ca=ca.cert)

    def login(self, cn):
        return self.domain.login(cn)

    def lock(self, d, cn):
        """Lock the account cn with wrong passwords; the DC must then show it as locked."""
        for _ in range(LOCKOUT_THRESHOLD):
            with d.connect() as c:
                self.assertEqual(c.pap(self.login(cn), "wrong").status_name, "FAIL")
        self.assertNotEqual(ldap_attributes(self.domain.dn(cn), "lockoutTime").get("lockoutTime", "0"), "0",
                            f"{cn} is not locked")

    def test_lock_checks_the_lockout(self):
        """bob has no lockout policy: lock() must not pass on wrong passwords alone."""
        with self.assertRaisesRegex(AssertionError, "bob is not locked"):
            self.lock(self.start(), "bob")

    def test_pap(self):
        """No LDAP_FILTER: the AD default (sAMAccountName) finds the user."""
        d = self.start()
        for password, status in (("alice-pw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("alice"), password).status_name, status)

    def test_ca_path_with_quotes(self):
        """The back-end gets a CA path with quotes and a backslash; with CHECKS_CA, another CA there fails."""
        other = CA("ad-other")
        self.addCleanup(other.remove)
        with tempfile.TemporaryDirectory() as tmp:
            ca = os.path.join(tmp, "it's \"a\" \\t", "ca.pem")
            os.mkdir(os.path.dirname(ca))
            for name, source, passes in (("dc", settings()["TACTEST_SAMBA_CA"], True),
                                         ("other", other.cert, not self.CHECKS_CA)):
                shutil.copy(source, ca)
                with mock.patch.dict(os.environ, TACTEST_SAMBA_CA=ca):
                    d = self.start()
                with self.subTest(ca=name), d.connect() as c:
                    self.assertEqual(c.pap(self.login("alice"), "alice-pw").status_name == "PASS", passes)

    def test_ascii_login(self):
        d = self.start()
        for password, status in (("bob-pw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.ascii_login(self.login("bob"), password).status_name, status)

    def test_unknown_user(self):
        d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap(self.login("nobody"), "alice-pw").status_name, "FAIL")

    def test_filter_characters(self):
        """No user name filter in the daemon: alice passes, a name with LDAP filter characters finds no user."""
        alice = self.login("alice")
        for name in (alice + "(", alice[:-1] + "*"):
            # a daemon for each name: a backend error can start the authentication fallback
            d = self.start(config="\tacl any_user { permit }\n\tmavis user filter = any_user\n")
            for user, status in ((alice, "PASS"), (name, "FAIL")):
                with self.subTest(name=name, user=user), d.connect() as c:
                    self.assertEqual(c.pap(user, "alice-pw").status_name, status)

    def test_groups(self):
        """memberOf of AD, nested: the group names become TACMEMBER, the group DNs MEMBEROF."""
        d = self.start()
        for user, motd in (("alice", "netadmins in staff\n"), ("dave", "staff\n"), ("bob", "")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(self.login(user), user + "-pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_posixgroup(self):
        """On AD the back-ends skip the posixGroup search, unless LDAP_SKIP_POSIXGROUP=0."""
        for env, motd in (({}, ""), ({"LDAP_SKIP_POSIXGROUP": "0"}, "unix\n")):
            d = self.start(**env)
            with self.subTest(env=env), d.connect() as c:
                r = c.ascii_login(self.login("posix"), "posix-pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_password_change(self):
        """The password change dialog sets unicodePwd (UTF-16LE: the new password is not ASCII)."""
        d = self.start()
        new = "carol-neu-ä€"
        with d.connect() as c:
            r = c.ascii_login(self.login("carol"), "", data=["wrong", new, new])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "FAIL"], r)
        with d.connect() as c:
            r = c.ascii_login(self.login("carol"), "", data=["carol-pw", new, new])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        for password, status in ((new, "PASS"), ("carol-pw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("carol"), password).status_name, status)

    def test_disabled_no_password_change(self):
        """A disabled account (533) gets no password change dialog, and its password stays."""
        d = self.start()
        with d.connect() as c:
            r = c.ascii_login(self.login("inactive"), "inactive-pw", data=["inactive-new", "inactive-new"])
        self.assertEqual(r.statuses, ["GETPASS", "FAIL"], r)
        self.assertEqual([self.domain.bind_code("inactive", p) for p in ("inactive-pw", "inactive-new")],
                         ["533", "52e"])

    def test_bind_errors(self):
        """The correct password of an account that AD does not let log in: FAIL, also without a password change."""
        d = self.start()
        self.lock(d, "locked")
        self.domain.wait_password_expired()
        for user, code, _ in BIND_ERRORS:
            with self.subTest(user=user, code=code), d.connect() as c:
                self.assertEqual(c.pap(self.login(user), user + "-pw").status_name, "FAIL")
            if code in ("773", "532"):
                continue
            with self.subTest(user=user, code=code, login="ascii"), d.connect() as c:
                self.assertEqual(c.ascii_login(self.login(user), user + "-pw").statuses, ["GETPASS", "FAIL"])


    def test_bind_error_messages(self):
        """The text for the "data" code of the AD bind error goes to the client."""
        d = self.start()
        self.lock(d, "lockmsg")
        self.domain.wait_password_expired()
        for user, code, text in BIND_ERRORS + (("alice", "52e", "Invalid credentials."),):
            user = "lockmsg" if user == "locked" else user     # test_bind_errors locks "locked"
            password = "wrong" if user == "alice" else user + "-pw"
            with self.subTest(user=user, code=code), d.connect() as c:
                r = c.pap(self.login(user), password)
                self.assertEqual((r.status_name, r.server_msg), ("FAIL", self.MESSAGE % text + "\n"), r)

    def test_must_change(self):
        """A password that must change (773) or that expired (532) starts the password change dialog."""
        d = self.start()
        self.domain.wait_password_expired()
        for user in ("reset", "aged"):
            new = user + "-new"
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(self.login(user), user + "-pw", data=[new, new])
                self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        # the policy of aged lets its new password expire at once
        for password, status in (("reset-new", "PASS"), ("reset-pw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("reset"), password).status_name, status)

    def test_must_change_bound(self):
        """After a 773 bind error, the password change runs bound: a failed bind leaves no identity (RFC 4511 4.2.1)."""
        # Samba keeps the identity of the earlier bind, so only the LDAP messages show the error
        relay, d = self.start_relay()
        with d.connect() as c:
            r = c.ascii_login(self.login("renew"), "renew-pw", data=["renew-new", "renew-new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        dn = self.domain.dn("renew")
        events = relay.events
        modifies = [k for k, (_, op, value) in enumerate(events) if op == "modify" and value.lower() == dn.lower()]
        self.assertTrue(modifies, f"no modify of {dn}: {events}")
        for k in modifies:
            results = [value for conn, op, value in events[:k] if conn == events[k][0] and op == "bound"]
            self.assertEqual(results[-1:], [0], f"event {k}, the modify of {dn}, follows a failed bind: {events}")
        with d.connect() as c:
            self.assertEqual(c.pap(self.login("renew"), "renew-new").status_name, "PASS")

    def test_must_change_groups_bound(self):
        """After a 773 bind error, the group searches of the AUTH request run bound, as the password change."""
        relay, d = self.start_relay()
        with d.connect() as c:
            r = c.ascii_login(self.login("grouped"), "grouped-pw", data=["grouped-new", "grouped-new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        events = relay.events
        searches = [k for k, (_, op, _) in enumerate(events) if op == "search"]
        self.assertTrue(searches, events)
        for k in searches:
            results = [value for conn, op, value in events[:k] if conn == events[k][0] and op == "bound"]
            self.assertIn(results[-1:], ([], [0]), f"event {k}, a search, follows a failed bind: {events}")

    def test_must_change_rebind_fails(self):
        """A failed LDAP_USER bind after the 773 bind error gives a backend error (ERROR), and no change."""
        # the change dialog (empty password) sends no AUTH: only the LDAP_USER bind before the change follows a 773
        relay, d = self.start_relay(refuse=self.domain.dn("reader"))
        with d.connect() as c:
            r = c.ascii_login(self.login("refused"), "", data=["refused-pw", "refused-new", "refused-new"])
        dn = self.domain.dn("refused")
        events = relay.events
        modifies = [k for k, (_, op, value) in enumerate(events) if op == "modify" and value.lower() == dn.lower()]
        self.assertEqual(relay.refused, self.CHPW_REBIND, events)
        if self.CHPW_REBIND:
            # the client gets FAIL also for a backend error
            self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "FAIL"], r)
            self.assertEqual(modifies, [], events)
            self.assertEqual(self.domain.bind_code("refused", "refused-pw"), "773")
        else:
            self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
            self.assertEqual(self.domain.bind_code("refused", "refused-new"), "")
        # only after a backend error can the fallback-only user log in
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS" if self.CHPW_REBIND else "FAIL")


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
class AdMt(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external-mt"
    EXEC = f'"{LDAPMAVIS}" "ldapmavis-mt"'
    MESSAGE = "Permission denied: %s"

    def env(self, ca):
        return {"LDAP_OPT_X_TLS_CACERTFILE": ca,
                "LDAP_OPT_X_TLS_REQUIRE_CERT": "LDAP_OPT_X_TLS_DEMAND"}


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class AdPerl(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external"
    EXEC = f'"{PERL}" "perl" "{LDAP_PERL}"'
    MESSAGE = "%s"
    # it changes the AD password as LDAP_USER, with no user bind
    CHPW_REBIND = False

    def env(self, ca):
        # IO::Socket::SSL counts the timeout in whole seconds: with 1 s, an LDAPS handshake over a second boundary fails
        return {"TLS_OPTIONS": f"verify => 'require', cafile => {perl_string(ca)}",
                "LDAP_CONNECT_TIMEOUT": "5"}


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(python_ldap3(), f"no ldap3 module for {PYTHON}")
class AdPython(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external"
    EXEC = f'"{PYTHON}" "python3" "{LDAP_PYTHON}"'
    MESSAGE = "Permission denied: %s"
    # ldap3 cannot match an IP address in the certificate; the certificate of the DC also names localhost
    NAMES = "valid_names=['localhost']"
    # it changes the password of a 773 or 532 account on its LDAP_USER connection, with no bind there
    CHPW_REBIND = False

    def env(self, ca):
        return {"TLS_OPTIONS": f"ca_certs_file={ca!r}, {self.NAMES}"}

    def test_tls_server_certificate_is_checked(self):
        """By default the back-end checks the certificate of the server: a CA it does not trust is a backend error."""
        trusted = self.env(settings()["TACTEST_SAMBA_CA"])["TLS_OPTIONS"]
        for options, status in ((None, "FAIL"), (self.NAMES, "FAIL"), (trusted, "PASS"),
                                ("validate=ssl.CERT_NONE", "PASS")):
            d = self.start(TLS_OPTIONS=options)
            with self.subTest(options=options), d.connect() as c:
                self.assertEqual(c.pap(self.login("alice"), "alice-pw").status_name, status)
            with self.subTest(options=options, user="rescue"), d.connect() as c:
                self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS" if status == "FAIL" else "FAIL")

    def test_tls_options_invalid(self):
        """An invalid TLS_OPTIONS stops the back-end with a message on stderr; the message does not show the values."""
        # Python 3.8 and 3.9 do not name the class in the TypeError
        unknown = r"(Tls\.)?__init__\(\) got an unexpected keyword argument 'nonsense'"
        cases = (("nonsense=1", rf"invalid TLS_OPTIONS \(nonsense\): {unknown}"),
                 ("local_private_key_password='s3cret', nonsense=1",
                  rf"invalid TLS_OPTIONS \(local_private_key_password, nonsense\): {unknown}"),
                 ("local_private_key_password=s3cret", r"invalid TLS_OPTIONS: NameError"))
        for i, (options, message) in enumerate(cases):
            with self.subTest(options=options):
                log = self.scratch_file(f"python-{i}.log", "")
                status = self.scratch_file(f"python-{i}.status", "")
                # MAVIS logs the stderr of the back-end to syslog only; the exit status follows the complete stderr
                script = f'#!/bin/sh\n"{PYTHON}" "{LDAP_PYTHON}" 2>>"{log}"\necho $? >>"{status}"\n'
                wrapper = self.scratch_file(f"python-{i}.sh", script)
                os.chmod(wrapper, 0o755)
                # the worker starts the back-end when it starts; check=False: the back-end exits on purpose
                self.start(command=f'"{wrapper}" "python3"', check=False, TLS_OPTIONS=options)
                deadline = time.monotonic() + 10
                while os.path.getsize(status) == 0 and time.monotonic() < deadline:
                    time.sleep(0.1)
                with open(status) as f:
                    self.assertEqual(f.read().split()[:1], ["1"], "the back-end did not exit with status 1")
                with open(log) as f:
                    text = f.read()
                self.assertNotIn("s3cret", text)
                self.assertRegex(text, message)


class DomainCleanup(unittest.TestCase):
    """The class cleanup of the AD tests, with stand-ins for the ldap-utils commands (no DC needed)."""

    # like OpenLDAP: one DN as the last argument, or with -c the DNs on stdin and the last nonzero exit code
    LDAPDELETE = """for a; do :; done
if [ "$a" = -c ]; then cat; else echo "$a"; fi | {
    rc=0
    while IFS= read -r dn; do
        echo "$dn" >> "$TACTEST_LDAP_LOG"
        case $dn in
            CN=*-expired,*) code=${DELETE_EXPIRED:-0};;
            CN=*-lockout,*) code=${DELETE_LOCKOUT:-0};;
            *) code=0;;
        esac
        [ "$code" = 0 ] || rc=$code
    done
    exit $rc
}"""

    def run_class(self, expired, lockout):
        """Run the setup and the cleanup of an AdTests class; returns the result and the DNs that ldapdelete got."""
        with tempfile.TemporaryDirectory() as tmp:
            ldif = "dn: x\n" + "".join(f"{k}: {v}\n" for k, v in DOMAIN_POLICY.items())
            with open(os.path.join(tmp, "policy.ldif"), "w") as f:
                f.write(ldif)
            for tool, body in (("ldapadd", "cat > /dev/null"), ("ldapsearch", f'cat "{tmp}/policy.ldif"'),
                               ("ldapdelete", self.LDAPDELETE)):
                with open(os.path.join(tmp, tool), "w") as f:
                    f.write("#!/bin/sh\n" + body + "\n")
                os.chmod(os.path.join(tmp, tool), 0o755)
            log = os.path.join(tmp, "ldapdelete.log")
            env = dict({k: "x" for k in SETTINGS}, DELETE_EXPIRED=str(expired), DELETE_LOCKOUT=str(lockout),
                       TACTEST_LDAP_LOG=log, PATH=tmp + os.pathsep + os.environ["PATH"])

            class Probe(AdTests, unittest.TestCase):
                def test_nothing(self):
                    pass

            result = unittest.TestResult()
            with mock.patch.dict(os.environ, env), mock.patch(f"{__name__}.URL", "ldaps://127.0.0.1:1"):
                unittest.TestSuite([Probe("test_nothing")]).run(result)
            with open(log) as f:
                return result, f.read().splitlines()

    def errors(self, result):
        return "\n".join(text for _, text in result.errors)

    def test_failed_pso_delete_is_an_error_when_the_other_pso_is_absent(self):
        """32 (no such object) of one PSO must not hide the failure of the other."""
        result, _ = self.run_class(expired=50, lockout=32)
        self.assertIn("ldapdelete failed (50)", self.errors(result))

    def test_each_pso_delete_runs_when_one_fails(self):
        for expired, lockout in ((50, 0), (0, 50)):
            with self.subTest(expired=expired, lockout=lockout):
                result, deleted = self.run_class(expired=expired, lockout=lockout)
                self.assertIn("ldapdelete failed (50)", self.errors(result))
                self.assertEqual(sorted(dn.split(",", 1)[0].rsplit("-", 1)[1] for dn in deleted if dn.startswith("CN=")),
                                 ["expired", "lockout"], deleted)

    def test_ou_delete_runs_when_a_pso_delete_fails(self):
        result, deleted = self.run_class(expired=50, lockout=0)
        self.assertIn("ldapdelete failed (50)", self.errors(result))
        self.assertTrue([dn for dn in deleted if dn.startswith("OU=tactest-")], deleted)

class SambaDcStart(unittest.TestCase):
    """samba-dc/start with stand-ins for docker and openssl (no DC needed)."""

    START = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samba-dc", "start")

    def test_missing_timeout(self):
        """Without the timeout command, start stops before the image build, with a message that names it."""
        with tempfile.TemporaryDirectory() as tmp:
            for tool in ("dirname", "mkdir", "cksum", "cut", "sed", "sleep"):
                os.symlink(shutil.which(tool), os.path.join(tmp, tool))
            log = os.path.join(tmp, "docker.log")
            # the container stops at once: without timeout, start then says that the DC does not answer
            for tool, body in (("docker", f'echo "$1" >> "{log}"\ncase $1 in port) echo 127.0.0.1:1;; '
                                          'inspect) echo false;; esac'),
                               ("openssl", "echo 00")):
                with open(os.path.join(tmp, tool), "w") as f:
                    f.write("#!/bin/sh\n" + body + "\n")
                os.chmod(os.path.join(tmp, tool), 0o755)
            p = subprocess.run(["/bin/sh", self.START], env={"PATH": tmp}, capture_output=True, text=True,
                               check=False)
            ran = os.path.exists(log)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("start: the timeout command is missing", p.stderr)
        self.assertFalse(ran, "start ran docker")


if __name__ == "__main__":
    unittest.main()
