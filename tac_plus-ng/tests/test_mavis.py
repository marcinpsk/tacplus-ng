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


"""MAVIS: the external module with the stub backend (tactest/mavis_stub.py)."""

import base64
import glob
import grp
import json
import os
import pwd
import re
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tactest import (GROUP_DB, LINUX, SOURCE, DaemonTestCase, Stub, config, detect, features, prefix,
                     run_with_group_db)
from tactest.daemon import alive as daemon_alive, parse_only, sanitizer_env, sanitizers

BACKEND = """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
"""

PERMIT = """
	ruleset {
		rule { script { permit } }
	}
"""


class Scenario(DaemonTestCase):
    """The stub changes its answers between requests, the daemon keeps running."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)
        self.stub.set(users={"alice": {"password": "first"}})

    def test_scenario_changes_without_restart(self):
        """The state file is read for every request; "mavis cache timeout = 0" keeps the daemon from caching."""
        before = self.stub.count()
        self.assertEqual(self.connect().pap("alice", "first").status_name, "PASS")
        self.stub.set(users={"alice": {"password": "second"}})
        self.assertEqual(self.connect().pap("alice", "first").status_name, "FAIL")
        self.assertEqual(self.connect().pap("alice", "second").status_name, "PASS")
        auth = [e for e in self.stub.requests()[before:] if (e["type"], e["user"]) == ("AUTH", "alice")]
        self.assertEqual([e["result"] for e in auth], ["ACK", "NAK", "ACK"])
        self.assertEqual(len({e["pid"] for e in auth}), 1, "one MAVIS child expected: %s" % auth)

    def test_forced_results(self):
        """ERROR from the backend is an ERROR for the client (without "authentication fallback = permit")."""
        for result, status in (("ACK", "PASS"), ("NAK", "FAIL"), ("NOTFOUND", "FAIL"), ("ERROR", "ERROR")):
            with self.subTest(result=result):
                self.stub.set(users={"alice": {"password": "first"}}, result={"alice:AUTH": result})
                self.assertEqual(self.connect().pap("alice", "wrong").status_name, status)

    def test_failure_with_a_multiline_message(self):
        """A FAIL with an LDAP error text from the backend must be answered at once.

        The client of #58 waited for a timeout. A line break in the text was
        the first suspect; it is fine (mavis.py sends it as CR). The cause
        was a NUL byte, see test_issue266.py.
        """
        self.stub.set(users={"alice": {"password": "first"}},
                      message="80090308: LdapErr: DSID-0C09044E\ncomment: AcceptSecurityContext error")
        for login in (self.connect().ascii_login, self.connect().pap):
            with self.subTest(login=login.__name__):
                self.assertEqual(login("alice", "wrong").status_name, "FAIL")

    def test_long_user_response_is_cut(self):
        """eval_log_format() has an 8000-byte buffer; a longer user response must be cut, not written past it."""
        self.stub.set(users={"alice": {"password": "first"}}, message="x" * 10000)
        r = self.connect().ascii_login("alice", "first")
        self.assertEqual(r.status_name, "PASS", r)
        self.assertLess(len(r.server_msg), 8000)
        self.assertEqual(set(r.server_msg), {"x"})
        self.assertGreater(len(r.server_msg), 7900)


class BackendFailed(DaemonTestCase):
    """An ASCII login with an ERROR from the backend gets ERROR and the BACKEND_FAILED message (doc: "User Messages")."""

    CONFIG = None

    def login(self, policy=""):
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT + policy)
        Stub(d).set(users={"alice": {"password": "pw"}}, result={"alice:AUTH": "ERROR"})
        r = self.connect(daemon=d).ascii_login("alice", "pw")
        return r.status_name, r.server_msg

    def test_default_message(self):
        self.assertEqual(self.login(), ("ERROR", "Authentication backend failure."))

    def test_configured_message(self):
        self.assertEqual(self.login('\tmessage BACKEND_FAILED = "Directory down."\n'), ("ERROR", "Directory down."))


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class BackendFailedNotAscii(DaemonTestCase):
    """An ERROR from the backend is an ERROR for the client also for a password change, PAP and enable."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND.replace("login backend = mavis", "login backend = mavis chpass") + """
	device paplogin {
		address = 127.0.0.91
		key = tactest
		pap password mapping = login
	}
	device enablelogin {
		address = 127.0.0.92
		key = tactest
		enable 15 = login
		augmented-enable = permit
	}
""" + PERMIT
    BACKEND_FAILED = ("ERROR", "Authentication backend failure.")

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)

    def backend_error(self, tactype):
        self.stub.set(users={"alice": {"password": "old", "new_password": "new"}}, result={"alice:" + tactype: "ERROR"})

    def answer(self, r):
        return r.status_name, r.server_msg

    def test_password_change_dialog(self):
        self.backend_error("CHPW")
        before = self.stub.count(type="CHPW")
        r = self.connect().ascii_login("alice", "", data=["old", "new", "new"])
        self.assertEqual(self.answer(r), self.BACKEND_FAILED, r)
        self.assertEqual([e["result"] for e in self.stub.requests(type="CHPW")[before:]], ["ERROR"])
        self.wait_log("authentication", "\talice\ttty0\t127.0.0.1\tpassword change failed (backend error)")

    def test_change_password_request(self):
        """The TACACS+ CHPASS action of RFC 8907 5.4.4.3."""
        self.backend_error("CHPW")
        s = self.connect().session()
        r = s.dialog(s.start(user="alice", action=2), {"GETDATA": ["old"], "GETPASS": ["new", "new"]})
        self.assertEqual(self.answer(r), self.BACKEND_FAILED, r)

    def test_pap(self):
        self.backend_error("AUTH")
        self.assertEqual(self.answer(self.connect().pap("alice", "old")), self.BACKEND_FAILED)
        self.wait_log("authentication", "\talice\ttty0\t127.0.0.1\tpap login failed (backend error)")

    def test_pap_mapped_to_login(self):
        self.backend_error("AUTH")
        self.assertEqual(self.answer(self.connect(source="127.0.0.91").pap("alice", "old")), self.BACKEND_FAILED)

    def test_enable_with_the_login_password(self):
        self.backend_error("AUTH")
        r = self.connect(source="127.0.0.92").enable("old", user="alice")
        self.assertEqual((r.statuses, r.server_msg), (["GETPASS", "ERROR"], self.BACKEND_FAILED[1]), r)

    def test_augmented_enable(self):
        self.backend_error("AUTH")
        # two answers: after the MAVIS answer the daemon asks a MAVIS user again
        r = self.connect(source="127.0.0.92").enable(["alice old", "alice old"], user="$enable$")
        self.assertEqual(self.answer(r), self.BACKEND_FAILED, r)


class BackendFailedWithFallback(DaemonTestCase):
    """With "authentication fallback = permit" an ERROR from the backend stays a FAIL for the client."""

    CONFIG = None

    def test_password_change(self):
        policy = Stub.module(childs=(1, 1)) + BACKEND.replace("login backend = mavis", "login backend = mavis chpass")
        d = self.start_daemon(policy + "\tauthentication fallback = permit\n" + PERMIT)
        Stub(d).set(users={"alice": {"password": "old", "new_password": "new"}}, result={"alice:CHPW": "ERROR"})
        with d.connect() as c:
            r = c.ascii_login("alice", "", data=["old", "new", "new"])
        self.assertEqual(r.status_name, "FAIL", r)


class Fallback(DaemonTestCase):
    """#98: after an ERROR from the backend a fallback-only user logs in with the local password.

    #98 itself was ldapmavis-mt not passing the backend error on (ee6eeb7);
    these tests pin the daemon's side of it. The realm remembers the failure for "authentication fallback period"
    (60 s), so every test has a daemon of its own.
    """

    CONFIG = None
    POLICY = Stub.module(childs=(1, 1)) + BACKEND + """
	authentication fallback = permit
	user rescue {
		fallback-only
		password login = clear rescuepw
		password pap = clear rescuepw
	}
""" + PERMIT

    def daemon_and_stub(self, **state):
        d = self.start_daemon(self.POLICY)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, **state)
        return d, stub

    def test_issue98_backend_error_lets_the_fallback_user_in(self):
        d, stub = self.daemon_and_stub(result={"*": "ERROR"})
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "FAIL")
        self.assertEqual(stub.requests()[-1]["result"], "ERROR")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")
            self.assertEqual(c.ascii_login("rescue", "rescuepw").status_name, "PASS")
            self.assertEqual(c.pap("rescue", "wrong").status_name, "FAIL")

    def test_issue98_no_fallback_while_the_backend_works(self):
        d, stub = self.daemon_and_stub()
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")


DACL_NAS = "127.0.0.6"
DACL_SECRET = "radsecret"
DACL_ACE = "permit ip host 1.2.3.4 any"
CISCO_VENDOR = 9
VENDOR_SPECIFIC = 26


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class DaclAnsweredAtOnce(DaemonTestCase):
    """A DACL from a MAVIS module that answers at once, without a back-end round trip (tacinfo_cache).

    mavis_dacl_lookup() gave such an answer to the user handler instead of
    the DACL handler, so the daemon did not apply the DACL and rejected
    the download.
    """

    CONFIG = None
    POLICY = """
	include = "%s"
	mavis module = tacinfo_cache { directory = "@CACHE@" }
""" % os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg") + Stub.module(childs=(1, 1)) + BACKEND + """
	device radius-nas {
		address = %s
		radius.key = %s
	}
""" % (DACL_NAS, DACL_SECRET) + PERMIT

    def test_dacl_from_the_cache_is_applied(self):
        # a short path: tacinfo_cache keeps only 36 characters of the cache file path (libmavis_tacinfo_cache.c)
        cache = tempfile.mkdtemp(prefix="tacinfo-", dir="/tmp")
        self.addCleanup(shutil.rmtree, cache)
        d = self.start_daemon(self.POLICY.replace("@CACHE@", cache), udp=True)
        stub = Stub(d)
        stub.set(dacls={"demoacl": '{ data = "%s" }' % DACL_ACE})
        event = b"aaa:event=acl-download"
        for source in ("backend", "cache"):
            with self.subTest(source=source):
                r = self.radius(DACL_SECRET, daemon=d, source=DACL_NAS).access_request(
                    "#ACSACL#demoacl-00000000", "", message_authenticator=True,
                    attributes=[(VENDOR_SPECIFIC, struct.pack("!IBB", CISCO_VENDOR, 1, len(event) + 2) + event)])
                self.assertEqual(r.code_name, "Access-Accept", r)
                self.assertIn(b"ip:inacl#1=" + DACL_ACE.encode(), b"".join(r.get(VENDOR_SPECIFIC)), r)
        # the second answer came from tacinfo_cache
        self.assertEqual([e["type"] for e in stub.requests()], ["DACL"])


def open_files_under(daemon, directory):
    """Paths under directory that the workers of daemon hold open (Linux)."""
    out = []
    for pid in daemon.workers():
        for fd in os.listdir("/proc/%d/fd" % pid):
            try:
                target = os.readlink("/proc/%d/fd/%s" % (pid, fd))
            except OSError:
                continue
            if target.startswith(directory + "/"):
                out.append(target)
    return out


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses, open files are found through /proc")
class DaclCacheExpired(DaemonTestCase):
    """tacinfo_cache closes a cache file that is older than "dacl cache timeout".

    mavis_send_in() returned MAVIS_DOWN for such a file without closing it,
    so the worker kept one descriptor for every expired entry it found.
    """

    CONFIG = None
    POLICY = DaclAnsweredAtOnce.POLICY.replace('directory = "@CACHE@" }',
                                               'directory = "@CACHE@" dacl cache timeout = 1 }')
    ROUNDS = 4

    def test_expired_cache_file_is_closed(self):
        self.assertIn("dacl cache timeout = 1", self.POLICY)
        cache = tempfile.mkdtemp(prefix="tacinfo-", dir="/tmp")
        self.addCleanup(shutil.rmtree, cache)
        d = self.start_daemon(self.POLICY.replace("@CACHE@", cache), udp=True)
        stub = Stub(d)
        stub.set(dacls={"demoacl": '{ data = "%s" }' % DACL_ACE})
        event = b"aaa:event=acl-download"
        for i in range(self.ROUNDS):
            if i:
                time.sleep(2.1)     # mtime + 1 < now: the entry of the last round has expired
            r = self.radius(DACL_SECRET, daemon=d, source=DACL_NAS).access_request(
                "#ACSACL#demoacl-00000000", "", message_authenticator=True,
                attributes=[(VENDOR_SPECIFIC, struct.pack("!IBB", CISCO_VENDOR, 1, len(event) + 2) + event)])
            self.assertEqual(r.code_name, "Access-Accept", r)
            self.assertTrue(d.workers(), "no worker found")
            with self.subTest(round=i):
                self.assertEqual(open_files_under(d, cache), [])
        # every round after the first found an expired entry and asked the backend again
        self.assertEqual([e["type"] for e in stub.requests()], ["DACL"] * self.ROUNDS)


class Cache(DaemonTestCase):
    """#69: authorization after authentication takes the user from the MAVIS cache."""

    CONFIG = None
    POLICY = Stub.module(childs=(1, 1)) + BACKEND + """
	profile admin {
		script { if (service == shell) { set priv-lvl = 15 permit } }
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
"""

    def login_then_authorize(self, template):
        d = self.start_daemon(self.POLICY, template=template)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}})
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
            before = stub.count()
            r = c.author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        return stub.requests()[before:]

    def test_issue69_authorization_uses_the_cache_by_default(self):
        """#69: the default cache period (120 s) was lost, every authorization asked the backend again."""
        template = config.BASE.replace("\tmavis cache timeout = 0\n", "")
        self.assertNotEqual(template, config.BASE)
        self.assertEqual(self.login_then_authorize(template), [])

    def test_authorization_asks_the_backend_without_cache(self):
        """The control: with "mavis cache timeout = 0" (the harness default) authorization sends INFO."""
        self.assertEqual([e["type"] for e in self.login_then_authorize(config.BASE)], ["INFO"])


class CachedPasswordChange(DaemonTestCase):
    """With a MAVIS cache period, a password change goes to the backend, and the old password is not cached.

    After a login the daemon caches a hash of the password as the login
    password of the user. do_chpass() then compared the new password with
    that hash and did not send CHPW to the backend.
    """

    CONFIG = None

    def setUp(self):
        super().setUp()
        template = config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = 60")
        self.assertNotEqual(template, config.BASE)
        policy = Stub.module(childs=(1, 1)) + BACKEND.replace("login backend = mavis", "login backend = mavis chpass")
        self.d = self.start_daemon(policy + PERMIT, template=template)
        self.stub = Stub(self.d)

    def login(self, password):
        with self.d.connect() as c:
            return c.ascii_login("alice", password).status_name

    def change(self, old, new):
        """The password change dialog: an empty password, then the old one and the new one twice."""
        with self.d.connect() as c:
            r = c.ascii_login("alice", "", data=[old, new, new])
        return r.status_name, r.server_msg

    def requests(self):
        return [(e["type"], e["result"]) for e in self.stub.requests()]

    def test_change_after_a_cached_login(self):
        self.stub.set(users={"alice": {"password": "old", "new_password": "new"}})
        self.assertEqual(self.login("old"), "PASS")
        self.assertEqual(self.change("old", "new"), ("PASS", "Password change succeeded."))
        self.assertEqual(self.requests(), [("AUTH", "ACK"), ("CHPW", "ACK")])
        self.stub.set(users={"alice": {"password": "new"}})
        self.assertEqual(self.login("old"), "FAIL")
        self.assertEqual(self.login("new"), "PASS")

    def test_second_change(self):
        self.stub.set(users={"alice": {"password": "old", "new_password": "new"}})
        self.assertEqual(self.change("old", "new"), ("PASS", "Password change succeeded."))
        self.stub.set(users={"alice": {"password": "new", "new_password": "newer"}})
        self.assertEqual(self.change("new", "newer"), ("PASS", "Password change succeeded."))
        self.assertEqual(self.requests(), [("CHPW", "ACK"), ("CHPW", "ACK")])
        self.stub.set(users={"alice": {"password": "newer"}})
        self.assertEqual(self.login("new"), "FAIL")
        self.assertEqual(self.login("newer"), "PASS")


def ssh_ed25519_key(size=32):
    """An OpenSSH public key line ("ssh-ed25519 <base64> comment"), the key itself made up."""
    def string(b):
        return struct.pack("!I", len(b)) + b
    blob = string(b"ssh-ed25519") + string(bytes(range(size)))
    return "ssh-ed25519 %s alice@example" % base64.b64encode(blob).decode()


GROUPS = ["group-with-a-rather-long-name-%03d" % i for i in range(200)]

# the "script out" of #189: append a group to whatever the backend returned
APPEND_GROUP = r"""
		script out {
			eval $$TACMEMBER =~ /^(.*)$$/
			set $$TACMEMBER = "$$1,\"no-login-profile\""
		}"""

GROUP_POLICY = BACKEND + "".join("\tgroup %s { }\n" % g for g in GROUPS) + """
	group no-login-profile { }
	profile admin {
		script { if (service == shell) { set priv-lvl = 15 permit } }
	}
	ruleset {
		rule last-group {
			script { if (member == %s && member == no-login-profile) { profile = admin permit } }
		}
	}
""" % GROUPS[-1]


@unittest.skipUnless("pcre2" in features(), "the script uses a PCRE")
class ManyGroups(DaemonTestCase):
    CONFIG = Stub.module(childs=(1, 1), script=APPEND_GROUP) + GROUP_POLICY

    def test_issue189_many_groups_through_script_out(self):
        """#189: "script out" copied TACMEMBER into a 4 kB buffer; with many groups only the appended one was left."""
        Stub(self.daemon).set(users={"alice": {"password": "pw", "member": GROUPS}})
        self.assertGreater(len(",".join('"%s"' % g for g in GROUPS)), 4096)
        self.assertEqual(self.connect().pap("alice", "pw").status_name, "PASS")
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))


@unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
class SshKeys(DaemonTestCase):
    """#194: SSH keys in OpenSSH format ("type base64 comment") from the backend.

    The fix (beba55f, after dc7a4a8 was reverted) is that backends send
    each key in double quotes, as mavis_tacplus-ng_ldap.pl,
    mavis_tacplus_ldap.py and ldapmavis-mt do; unquoted, the blanks
    break the profile parser and the whole request fails.
    """

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def test_issue194_openssh_key_from_the_backend(self):
        stub = Stub(self.daemon)
        key = ssh_ed25519_key()
        for keys in (['"%s"' % key], ['"%s"' % key, '"%s"' % key.replace("alice@", "laptop@")]):
            with self.subTest(keys=len(keys)):
                stub.set(users={"bob": {"password": "pw", "sshkey": ",".join(keys)}})
                self.assertEqual(self.connect().pap("bob", "pw").status_name, "PASS")


@unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
class SshKeyLength(DaemonTestCase):
    """An SSH key that decodes to fewer bytes than its fingerprint text has.

    The parser sized the stored fingerprint by the key length, so a key
    of 40 to 43 bytes (40 is the shortest it accepts) wrote past the
    allocation. Both a user in the configuration and one from the
    backend must log in.
    """

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT
    SHORT = ssh_ed25519_key(21)     # 40 bytes decoded
    NORMAL = ssh_ed25519_key()      # 51 bytes, a real ed25519 key

    def test_short_ssh_key_from_the_backend(self):
        self.assertEqual(len(base64.b64decode(self.SHORT.split()[1])), 40)
        stub = Stub(self.daemon)
        for key in (self.SHORT, self.NORMAL):
            with self.subTest(key=key.split()[1]):
                stub.set(users={"bob": {"password": "pw", "sshkey": '"%s"' % key}})
                self.assertEqual(self.connect().pap("bob", "pw").status_name, "PASS")

    def test_short_ssh_key_in_the_configuration(self):
        for key in (self.SHORT, self.NORMAL):
            with self.subTest(key=key.split()[1]):
                d = self.start_daemon("""
	user carol {
		password pap = clear carolpw
		ssh-key = "%s"
	}
""" % key + PERMIT)
                self.assertEqual(self.connect(d).pap("carol", "carolpw").status_name, "PASS")


@unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
class SshKeyRfc4716(DaemonTestCase):
    """#340: SSH keys in the RFC 4716 format ("---- BEGIN SSH2 PUBLIC KEY ----").

    The parser looked for the end of the header line and searched from
    there without a check, so a key that was only the begin marker (or
    whose header had no end) crashed the worker. A backend reaches that
    with any RFC 4716 key: its SSHKEY value is one key per line, so the
    daemon sees the marker line alone. Such a key is a parse error now,
    like any other key that does not decode.

    The buffer with the BASE64 text of the key was used after the end
    of its block; depending on the compiler a complete key in the
    configuration then failed to decode.
    """

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT
    BEGIN = "---- BEGIN SSH2 PUBLIC KEY ----"
    END = "---- END SSH2 PUBLIC KEY ----"
    BLOB = ssh_ed25519_key().split()[1]
    COMPLETE = (
        "%s\n%s\n%s\n" % (BEGIN, BLOB, END),
        "%s\nComment: alice\n%s\n%s\n" % (BEGIN, BLOB, END),
        "%s\n%s\n%s\n%s" % (BEGIN, BLOB[:40], BLOB[40:], END),
    )
    BROKEN = (
        BEGIN,                              # no end of the header line
        BEGIN + "\n",                       # nothing after it
        BEGIN + "\nComment: a\\b",          # a continuation without a next line
        BEGIN + "\nComment: alice",         # a header line without an end
        BEGIN + "\n" + BLOB,                # no end of the key line
    )

    def parse(self, key):
        path = self.scratch_file("tac_plus-ng.cfg", '''\
id = spawnd { listen { port = 4949 } }
id = tac_plus-ng {
	user carol {
		password pap = clear carolpw
		ssh-key = "%s"
	}
}
''' % key)
        return parse_only(path)

    def test_complete_key_in_the_configuration(self):
        for key in self.COMPLETE:
            with self.subTest(key=key):
                code, out = self.parse(key)
                self.assertEqual(code, 0, out)

    def test_broken_key_in_the_configuration(self):
        """The parser refuses the configuration; it is not killed by a signal."""
        for key in self.BROKEN:
            with self.subTest(key=key):
                code, out = self.parse(key)
                self.assertGreater(code, 0, out)
                self.assertIn("BASE64 decode of SSH key failed", out)

    def test_key_from_the_backend(self):
        """The login fails, the worker stays (the crash detectors run after the test)."""
        stub = Stub(self.daemon)
        for key in self.BROKEN + self.COMPLETE[:1]:
            with self.subTest(key=key):
                stub.set(users={"bob": {"password": "pw", "sshkey": '"%s"' % key}})
                self.assertEqual(self.connect().pap("bob", "pw").status_name, "FAIL")
        stub.set(users={"bob": {"password": "pw"}})
        self.assertEqual(self.connect().pap("bob", "pw").status_name, "PASS")


# "naskey" and "enablepw", encrypted with the type6-key "demo"
NASKEY_6 = r"KIXTPG^HRJ]FIdaO\IN]fRbFKaTAAB"
ENABLEPW_6 = r"JGRZhS_TGAab^`ZXC]XKadGG]ihdiNAAB"


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
class Type6HostProfile(DaemonTestCase):
    """The type6-key of a MAVIS host profile decrypts the type 6 values of that profile, also the earlier ones."""

    CONFIG = Stub.module(childs=(1, 1)) + """
	device mavis6 {
		address = 127.0.0.6
		mavis backend = yes
	}
	device mavis7 {
		address = 127.0.0.7
		mavis backend = yes
	}
	user alice {
		password pap = clear alicepw
	}
	type6-key = wrong
""" + PERMIT

    def setUp(self):
        super().setUp()
        Stub(self.daemon).set(hosts={
            "127.0.0.6": "{ key = 6 '%s' type6-key = demo }" % NASKEY_6,
            "127.0.0.7": "{ key = 6 '%s' type6-key = other }" % NASKEY_6,
        })

    def test_type6_key_after_the_value(self):
        self.assertEqual(self.connect(source="127.0.0.6", key="naskey").pap("alice", "alicepw").status_name, "PASS")

    def test_type6_value_the_profile_key_cannot_decrypt_rejects_the_host(self):
        self.assertRejected(source="127.0.0.7", msg="the daemon accepted the host")


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
class Type6UserProfile(DaemonTestCase):
    """The type6-key of the realm decrypts a type 6 value of a MAVIS user profile."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT + "\ttype6-key = demo\n"

    def setUp(self):
        super().setUp()
        Stub(self.daemon).set(users={"alice": {"password": "alicepw", "profile": "{ enable 15 = 6 '%s' }" % ENABLEPW_6}})

    def test_type6_enable(self):
        self.assertEqual(self.connect().enable("enablepw", user="alice").status_name, "PASS")

    def test_type6_enable_with_the_encrypted_text_fails(self):
        self.assertEqual(self.connect().enable(ENABLEPW_6, user="alice").status_name, "FAIL")


DAY = 86400


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class PasswordExpiry(DaemonTestCase):
    """The PASSWORD_EXPIRY of the backend selects the PASSWORD_EXPIRED or PASSWORD_EXPIRES message."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT + """
	device msgdev {
		address = 127.0.0.36
		key = tactest
		password expiry warning = 7d
		message PASSWORD_EXPIRED = "Your password is too old."
		message PASSWORD_EXPIRES = "Your password expires on %Y-%m-%d."
	}
"""

    def setUp(self):
        super().setUp()
        self.soon = int(time.time()) + 3 * DAY
        Stub(self.daemon).set(users={"old": {"password": "pw", "expiry": int(time.time()) - DAY},
                                     "soon": {"password": "pw", "expiry": self.soon}})

    def login(self, user, source=None):
        r = self.connect(source=source).ascii_login(user, "pw")
        return r.status_name, r.server_msg

    def test_password_expired(self):
        self.assertEqual(self.login("old", source="127.0.0.36"), ("PASS", "Your password is too old.\n"))

    def test_password_expires(self):
        expected = time.strftime("Your password expires on %Y-%m-%d.\n", time.localtime(self.soon))
        self.assertEqual(self.login("soon", source="127.0.0.36"), ("PASS", expected))

    def test_default_password_expired(self):
        self.assertEqual(self.login("old"), ("PASS", "Password has expired.\n"))


LIST_POLICY = BACKEND + r"""
	alias admins_alias { admins }
	group ops { }
	group admins { }
	group "a\"b" { }
	group "x\"y,z" { }
	ruleset {
		rule blocked { script { if (memberof == "cn=blocked\\,x,dc=example") { deny } } }
		rule blocked_quote { script { if (memberof == "cn=d\"e,f,dc=example") { deny } } }
		rule admins { script { if (member == admins) { motd banner = "admins\n" permit } } }
		rule quote { script { if (member == "a\"b") { motd banner = "quote\n" permit } } }
		rule quote_comma { script { if (member == "x\"y,z") { motd banner = "quote and comma\n" permit } } }
		rule comma { script { if (memberof == "cn=a\\,b,dc=example") { motd banner = "comma\n" permit } } }
		rule dn { script { if (memberof == "cn=q\\\"r,dc=example") { motd banner = "dn\n" permit } } }
		rule staff { script { if (memberof == "cn=staff,dc=example") { motd banner = "staff\n" permit } } }
		rule ops { script { if (member == ops) { motd banner = "ops\n" permit } } }
		rule everyone { script { permit } }
	}
"""


class ListValues(DaemonTestCase):
    """The list attributes of a backend: TACMEMBER, SSHKEY, SSHKEYHASH, SSHKEYID and MEMBEROF.

    A value is a comma separated list of the entries of its attribute.
    Inside double quotes a backslash escapes a double quote or a backslash.
    """

    CONFIG = Stub.module(childs=(1, 1)) + LIST_POLICY

    @classmethod
    def setUpClass(cls):
        # the daemon gets the environment of the tests
        os.environ["TACTEST_LIST_GROUP"] = "admins"
        cls.addClassCleanup(os.environ.pop, "TACTEST_LIST_GROUP")
        super().setUpClass()

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)

    def login(self, **attributes):
        self.stub.set(users={"bob": dict(password="pw", **attributes)})
        r = self.connect().ascii_login("bob", "pw")
        return r.status_name, r.server_msg

    def test_list_entries(self):
        for member, motd in (('"ops"', "ops\n"), ("ops", "ops\n"), ('"ops","admins"', "admins\n"),
                             ('"ops", admins', "admins\n"), ("ops,admins", "admins\n"), (r'"a\"b",ops', "quote\n"),
                             (r'"a\"b"', "quote\n"), ("'a\"b'", "quote\n"), (r'"op\\s"', ""),
                             (r'"x\"y,z"', "quote and comma\n"), (r'ops,"x\"y,z"', "quote and comma\n")):
            with self.subTest(member=member):
                self.assertEqual(self.login(member=member), ("PASS", motd))

    def test_value_is_literal(self):
        """A value of a backend is not a configuration text: no ${VAR}, no alias and no other escapes in it."""
        for member in ('"${TACTEST_LIST_GROUP}"', '"admins_alias"', r'"\141dmins"'):
            with self.subTest(member=member):
                self.assertEqual(self.login(member=member), ("PASS", ""))

    def test_value_has_only_entries_of_its_attribute(self):
        """Text after the list, a closing brace or an empty value is a parse error: the user does not log in."""
        for member in ('"ops" } { member = "admins"', '"ops" member = "admins"', '"ops" }', '"ops",', '"ops",,admins',
                       ',"ops"'):
            with self.subTest(member=member):
                self.assertEqual(self.login(member=member)[0], "FAIL")

    @unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
    def test_ssh_key_value_has_only_ssh_keys(self):
        key = ssh_ed25519_key()
        self.assertEqual(self.login(member="ops", sshkey='"%s"' % key), ("PASS", "ops\n"))
        self.assertEqual(self.login(member="ops", sshkey='"%s" } { member = "admins"' % key)[0], "FAIL")

    def test_memberof_deny_rule(self):
        """A memberof deny rule matches a DN with an escaped comma, and a DN with a quote and a comma."""
        for memberof in (r'"cn=blocked\,x,dc=example"', r'"cn=staff,dc=example","cn=blocked\,x,dc=example"',
                         r'"cn=d\"e,f,dc=example"', r'"cn=staff,dc=example","cn=d\"e,f,dc=example"'):
            with self.subTest(memberof=memberof):
                self.assertEqual(self.login(memberof=memberof)[0], "FAIL")

    def test_malformed_memberof_is_refused(self):
        """A MEMBEROF that is not a list of quoted values is a parse error, not a list that ends early."""
        for memberof in (r'"cn=staff,dc=example" "cn=blocked\,x,dc=example"', '"cn=staff,dc=example',
                         'cn=staff,dc=example', '"cn=staff,dc=example"x'):
            with self.subTest(memberof=memberof):
                self.assertEqual(self.login(memberof=memberof)[0], "FAIL")
        self.assertEqual(self.login(memberof='"cn=staff,dc=example"'), ("PASS", "staff\n"))

    def test_memberof_escapes(self):
        """A quote in a DN, escaped, is part of that DN and does not end the list.

        Only a backslash before the quote is an escape: a DN with an
        escaped comma or backslash keeps its bytes.
        """
        for memberof, motd in ((r'"cn=a\,b,dc=example"', "comma\n"), (r'"cn=q\\"r,dc=example","cn=staff,dc=example"', "dn\n"),
                               (r'"cn=a\"b,dc=example","cn=staff,dc=example"', "staff\n"),
                               (r'"cn=a\\b,dc=example","cn=staff,dc=example"', "staff\n")):
            with self.subTest(memberof=memberof):
                self.assertEqual(self.login(memberof=memberof), ("PASS", motd))


@unittest.skipUnless("pcre2" in features(), "the groups filter is a PCRE")
class ListValuesGroupsFilter(DaemonTestCase):
    """The groups module reads and writes the list attributes with the same escapes as the daemon."""

    CONFIG = """
	mavis module = groups {
		groups filter = /^(ops|a.b|x.y,z|root)$$/
		memberof filter = /staff|,b,|d.e,f/
		resolve gids = yes
		resolve gids attribute = TACMEMBER
	}
""" + Stub.module(childs=(1, 1)) + LIST_POLICY

    def test_malformed_list(self):
        """The groups module fails an answer with a malformed list, also with "resolve gids"; tac_plus-ng refuses it too."""
        stub = Stub(self.daemon)
        for attributes in ({"member": '"ops" "admins"'}, {"member": '"ops","admins'},
                           {"memberof": '"cn=staff,dc=example" "cn=x,dc=example"'}, {"memberof": 'cn=staff,dc=example'},
                           {"member": '"ops" "admins"', "gids": "0"}):
            with self.subTest(attributes=attributes):
                stub.set(users={"bob": dict(password="pw", **attributes)})
                r = self.connect().ascii_login("bob", "pw")
                self.assertEqual(r.status_name, "FAIL", r)

    def test_escaped_values_pass_the_filter(self):
        stub = Stub(self.daemon)
        for attributes, motd in (({"member": r'"a\"b","admins"'}, "quote\n"),
                                 ({"memberof": r'"cn=a\"b,dc=example","cn=staff,dc=example"'}, "staff\n"),
                                 ({"memberof": r'"cn=a\,b,dc=example"'}, "comma\n"),
                                 ({"member": r'"x\"y,z","admins"'}, "quote and comma\n")):
            with self.subTest(attributes=attributes):
                stub.set(users={"bob": dict(password="pw", **attributes)})
                r = self.connect().ascii_login("bob", "pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd))

    def test_deny_rule_after_the_filter(self):
        """The groups module writes a DN with a quote and a comma back as one value, and the deny rule matches it."""
        stub = Stub(self.daemon)
        for user, memberof in (("deny1", r'"cn=d\"e,f,dc=example"'),
                               ("deny2", r'"cn=staff,dc=example","cn=d\"e,f,dc=example"')):
            with self.subTest(memberof=memberof):
                stub.set(users={user: dict(password="pw", memberof=memberof)})
                self.assertEqual(self.connect().ascii_login(user, "pw").status_name, "FAIL")
                # the rule denies it, not a parse error
                self.wait_log("authentication", "\t%s\ttty0\t127.0.0.1\tshell login denied by ACL" % user)


@unittest.skipUnless("pcre2" in features(), "the script uses a PCRE")
class ScriptOnMalformedList(DaemonTestCase):
    """A "script out" of a module does not run on a malformed list: the answer fails, and the daemon refuses it too."""

    CONFIG = Stub.module(childs=(1, 1), script=r"""
		script out {
			if ($$TACMEMBER =~ /blocked/) {
				set $$RESULT = NAK
				return
			}
			eval $$MEMBEROF =~ /^(.*)$$/
			set $$MEMBEROF = $$1
		}""") + LIST_POLICY

    def test_script_out(self):
        stub = Stub(self.daemon)
        stub.set(users={"bob": {"password": "pw", "memberof": '"cn=staff,dc=example"'}})
        self.assertEqual(self.connect().ascii_login("bob", "pw").server_msg, "staff\n")
        stub.set(users={"bob": {"password": "pw", "memberof": '"cn=staff,dc=example"\n"cn=blocked\\,x,dc=example"'}})
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")
        stub.set(users={"bob": {"password": "pw", "member": '"ops",\n"blocked"'}})
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")


FAIL_CLOSED_POLICY = BACKEND + r"""
	device trusting {
		address = 127.0.10.1
		key = tactest
		permit if-authenticated = yes
	}
	group ops { }
	ruleset {
		rule format { script { if ("$${memberof}" =~ /staff/) { motd banner = "format\n" permit } } }
		rule new { script { if (member =~ /^newgrp/) { motd banner = "newgrp\n" permit } } }
		rule everyone { script { permit } }
	}
"""


@unittest.skipUnless("pcre2" in features(), "the rules use a PCRE")
class MalformedListValues(DaemonTestCase):
    """A reply with a malformed list is a FAIL in each place that reads the reply."""

    CONFIG = Stub.module(childs=(1, 1)) + FAIL_CLOSED_POLICY
    MALFORMED = ({"member": '"ops",'}, {"memberof": '"cn=staff,dc=example" "cn=x,dc=example"'},
                 {"member": '"ops"\n"newgrp"'}, {"memberof": '"cn=staff,dc=example"\n"cn=x,dc=example"'})

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)

    def set_user(self, name, **attributes):
        self.stub.set(users={name: dict(password="pw", **attributes)})

    def test_login(self):
        for attributes in self.MALFORMED:
            with self.subTest(attributes=attributes):
                self.set_user("bob", **attributes)
                self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")

    @unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
    def test_authorization_of_a_user_authenticated_on_the_device(self):
        """"permit if-authenticated" applies to a user the backend does not know, not to one with a malformed reply."""
        self.set_user("bob", member='"ops"')
        r = self.connect(source="127.0.10.1").author("nobody", ["service=shell", "cmd="], authen_method=5)
        self.assertEqual(r.status_name, "PASS_ADD")
        for attributes in self.MALFORMED:
            with self.subTest(attributes=attributes):
                self.set_user("bob", **attributes)
                r = self.connect(source="127.0.10.1").author("bob", ["service=shell", "cmd="], authen_method=5)
                self.assertEqual(r.status_name, "FAIL")

    def test_log_format_of_a_malformed_memberof(self):
        """The rule with "${memberof}" never sees a malformed list."""
        self.set_user("bob", memberof='"cn=staff,dc=example"')
        self.assertEqual(self.connect().ascii_login("bob", "pw").server_msg, "format\n")
        self.set_user("bob", memberof='"cn=staff,dc=example" x')
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")

    def test_no_group_from_a_malformed_list(self):
        """The values of a malformed list do not reach the groups of the realm."""
        for group, rest in (("newgrp1", '"x'), ("newgrp2", '"%s"' % ("x" * 0x10000))):
            with self.subTest(group=group):
                self.set_user("carol", member='"%s",%s' % (group, rest))
                self.assertEqual(self.connect().ascii_login("carol", "pw").status_name, "FAIL")
                self.set_user("dan", member=group)
                self.assertEqual(self.connect().ascii_login("dan", "pw").server_msg, "")

    @unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
    def test_no_group_from_an_answer_that_fails_later(self):
        """An answer with a valid TACMEMBER and an SSHKEY that fails adds no group to the realm."""
        for group, sshkey in (("newgrp3", '"%s"' % ("A" * 0x10000)), ("newgrp4", '"not a key"')):
            with self.subTest(group=group):
                self.set_user("carol", member='"%s"' % group, sshkey=sshkey)
                self.assertEqual(self.connect().ascii_login("carol", "pw").status_name, "FAIL")
                self.set_user("dan", member=group)
                self.assertEqual(self.connect().ascii_login("dan", "pw").server_msg, "")

    @unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
    def test_empty_ssh_key(self):
        self.set_user("bob", sshkey='""')
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")
        code, out = parse_only(self.scratch_file("tac_plus-ng.cfg", """\
id = spawnd { listen { port = 4949 } }
id = tac_plus-ng {
	user carol {
		password pap = clear carolpw
		ssh-key = ""
	}
}
"""))
        self.assertGreater(code, 0, out)
        self.assertIn("Empty SSH key", out)


class MalformedMemberofMfa(DaemonTestCase):
    """The "mavis mfa acl" on a malformed MEMBEROF: the login fails, it does not go on without MFA."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + """
	acl mfa-staff { if (memberof == "cn=staff,dc=example") permit }
	mavis mfa acl = mfa-staff
""" + PERMIT

    def test_mfa_acl(self):
        stub = Stub(self.daemon)
        stub.set(users={"bob": {"password": "pw", "memberof": '"cn=staff,dc=example" "cn=x,dc=example"'}})
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")
        self.assertEqual(stub.requests(type="MFA"), [])


def system_group():
    """A group of the system database other than gid 0, with a name that a configuration takes as it is."""
    for g in sorted(grp.getgrall(), key=lambda g: g.gr_gid):
        if g.gr_gid and re.fullmatch(r"[a-z_][a-z0-9_-]*", g.gr_name) and grp.getgrgid(g.gr_gid).gr_name == g.gr_name:
            return g
    return None


GROUP = system_group()


@unittest.skipUnless(GROUP, "no group other than gid 0 in the group database")
class GroupsResolveGids(DaemonTestCase):
    """"resolve gids attribute = TACMEMBER" with more names than the old 8 kB buffer took.

    The last gid is a group of the system database (gid 1 is "daemon" on Debian, "bin" on Alpine).
    """

    CONFIG = """
	mavis module = groups {
		resolve gids = yes
		resolve gids attribute = TACMEMBER
	}
""" + Stub.module(childs=(1, 1)) + BACKEND + """
	group %(name)s { }
	ruleset {
		rule last { script { if (member == %(name)s) { motd banner = "last\\n" permit } } }
		rule everyone { script { permit } }
	}
""" % {"name": GROUP.gr_name if GROUP else "none"}

    def test_all_names(self):
        Stub(self.daemon).set(users={"bob": {"password": "pw", "gids": "0," * 2100 + str(GROUP.gr_gid)}})
        r = self.connect().ascii_login("bob", "pw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "last\n"))


GROUP_GID = 4242


@unittest.skipUnless(LINUX and shutil.which("unshare"), "a user and mount namespace (Linux, unshare)")
@unittest.skipIf(os.environ.get(GROUP_DB), "runs only outside the namespace")
class GroupNameTheListCannotCarry(unittest.TestCase):
    """A name from "resolve gids" that MEMBEROF cannot carry (a backslash at the end) makes tac_plus-ng refuse the answer.

    The test runs GroupNameInNamespace in a user and mount namespace with a group database that has such a name.
    """

    def test_refused(self):
        run_with_group_db(self, "bs\\:x:%d:\n" % GROUP_GID, "test_mavis.GroupNameInNamespace")


@unittest.skipUnless(os.environ.get(GROUP_DB), "runs in the namespace of GroupNameTheListCannotCarry")
class GroupNameInNamespace(DaemonTestCase):
    CONFIG = """
	mavis module = groups {
		resolve gids = yes
		resolve gids attribute = MEMBEROF
	}
""" + Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def test_login(self):
        self.assertEqual(grp.getgrgid(GROUP_GID).gr_name, "bs\\")
        stub = Stub(self.daemon)
        stub.set(users={"bob": {"password": "pw", "gids": "0"}})
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "PASS")
        stub.set(users={"bob": {"password": "pw", "gids": "0,%d" % GROUP_GID}})
        self.assertEqual(self.connect().ascii_login("bob", "pw").status_name, "FAIL")


class PasswordChange(DaemonTestCase):
    """#30: a user who must change the password and cancels is asked again next time.

    The password was cached after the first login, so the second one was
    answered from the cache without asking the backend, and without the
    change. Hence a cache period here.
    """

    CONFIG = None

    def test_issue30_password_change_asked_again_after_abort(self):
        template = config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = 60")
        self.assertNotEqual(template, config.BASE)
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT, template=template)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "old", "mustchange": True}})
        with d.connect() as c:
            s = c.session()
            r = s.start(user="alice")
            self.assertEqual(r.status_name, "GETPASS", r)
            r = s.cont("old")
            self.assertEqual(r.status_name, "GETDATA", r)
            s.cont(abort=True)
            self.assertTrue(c.silent(1.0))
        with d.connect() as c:
            r = c.ascii_login("alice", "old", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH", "AUTH", "CHPW"])

    def test_new_passwords_do_not_match(self):
        """Two different new passwords end the dialog with FAIL; the message ends with a newline."""
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT)
        Stub(d).set(users={"alice": {"password": "old", "mustchange": True}})
        r = self.connect(daemon=d).ascii_login("alice", "old", data=["new", "other"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "FAIL"], r)
        self.assertEqual(r.server_msg, "Passwords do not match.\n", r)


# a backend with a challenge for the users whose name starts with otpuser; argv[1] is the directory of mavis.py
CHALRESP_BACKEND = """
import sys
sys.path.insert(0, sys.argv[1])
import mavis as M

while True:
	d = M.Mavis()
	user, tactype = d.av_pairs.get(M.AV_A_USER), d.av_pairs.get(M.AV_A_TACTYPE)
	if not (user or "").startswith("otpuser"):
		d.write(M.MAVIS_DOWN, M.AV_V_RESULT_NOTFOUND, None)
	elif tactype == M.AV_V_TACTYPE_CHAL:
		d.av_pairs[M.AV_A_CHALLENGE] = "otp-md5 99 tactest"
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK, None)
	elif tactype == M.AV_V_TACTYPE_AUTH:
		ok = d.av_pairs.get(M.AV_A_PASSWORD) == "response99"
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK if ok else M.AV_V_RESULT_FAIL, None)
	else:
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK, None)
"""


class ChallengeResponse(DaemonTestCase):
    """"login backend = mavis chalresp": the backend sends a challenge, the user answers it."""

    CONFIG = None

    def start(self, policy=""):
        script = self.scratch_file("backend.py", CHALRESP_BACKEND)
        return self.start_daemon("""
	mavis module = external {
		exec = "%s" "%s" "-u" "%s" "%s"
		childs min = 1
		childs max = 1
	}
	user backend = mavis
	login backend = mavis chalresp
""" % (sys.executable, sys.executable, script, os.path.join(prefix(), "lib", "mavis")) + policy + PERMIT)

    def prompt(self, policy="", user="otpuser", **kw):
        r = self.connect(daemon=self.start(policy)).ascii_login(user, "response99", **kw)
        self.assertTrue(r.ok, r)
        return r.prompts[-1]

    def test_right_response(self):
        self.assertTrue(self.connect(daemon=self.start()).ascii_login("otpuser", "response99").ok)

    def test_wrong_response_is_response_incorrect(self):
        """The RESPONSE_INCORRECT user message, as PASSWORD_INCORRECT for a password."""
        r = self.connect(daemon=self.start()).ascii_login("otpuser", "bad")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Response incorrect.\n"), r)

    def test_prompt_after_getuser(self):
        self.assertEqual(self.prompt(user_in_start=False), "otp-md5 99 tactest\nResponse: ")

    def test_prompt_without_banner(self):
        """The user is in START, so the GETPASS prompt is the first text the user sees."""
        self.assertEqual(self.prompt(), "\notp-md5 99 tactest\nResponse: ")

    def test_prompt_after_welcome_banner(self):
        """The line breaks around the challenge reach the client as line breaks, not as "\\012"."""
        self.assertEqual(self.prompt('\twelcome banner = "Welcome.\\n"\n'), "Welcome.\n\notp-md5 99 tactest\nResponse: ")

    def test_banner_escapes_the_user_name(self):
        """Only the challenge is unescaped: a control character in the user name from the client stays escaped."""
        prompt = self.prompt('\twelcome banner = "Hello $${user}.\\n"\n', user="otpuser\x07")
        self.assertEqual(prompt, "Hello otpuser\\007.\n\notp-md5 99 tactest\nResponse: ")


SHADOW = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_shadow.pl")


class MustChangeWithoutDialog(DaemonTestCase):
    """The backend answers OK with PASSWORD_MUSTCHANGE to a login that has no dialog for a new password.

    Only ASCII login and CHPASS can change a password. For PAP and CHAP
    the daemon set the MAVIS result to FAIL, but permitted the login
    anyway and cached the password. mavis_tacplus_shadow.pl sends
    PASSWORD_MUSTCHANGE for an expired password whatever the caller can do.
    """

    CONFIG = None
    MESSAGE = "Please change your password."

    def daemon_and_stub(self, policy=BACKEND, template=config.BASE):
        d = self.start_daemon(Stub.module(childs=(1, 1)) + policy + PERMIT, template=template)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw", "mustchange": True}}, message=self.MESSAGE)
        return d, stub

    def test_pap_fails_and_caches_nothing(self):
        template = config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = 60")
        d, stub = self.daemon_and_stub(template=template)
        for _ in range(2):
            with d.connect() as c:
                r = c.pap("alice", "pw")
            self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        # the second login was not answered from the cache
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("AUTH", "ACK"), ("AUTH", "ACK")])

    def test_pap_fails_and_drops_the_cached_login_password(self):
        """An ASCII login cached the password before it expired; the next ASCII login must ask the backend again."""
        template = config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = 60")
        d, stub = self.daemon_and_stub(policy=BACKEND.replace("login backend = mavis", "login backend = mavis chpass"),
                                       template=template)
        stub.set(users={"alice": {"password": "pw"}})
        with d.connect() as c:
            self.assertEqual(c.ascii_login("alice", "pw").statuses, ["GETPASS", "PASS"])
        stub.set(users={"alice": {"password": "pw", "mustchange": True}}, message=self.MESSAGE)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "FAIL")
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH", "AUTH", "AUTH", "CHPW"])

    def test_chap_fails(self):
        d, stub = self.daemon_and_stub(policy=BACKEND + "\tchap backend = mavis\n")
        stub.set(users={"alice": {"password": "pw", "mustchange": True}}, result={"CHAP": "ACK"})
        with d.connect() as c:
            self.assertEqual(c.chap("alice", "pw").status_name, "FAIL")
        self.assertEqual([e["type"] for e in stub.requests()], ["INFO", "CHAP"])

    def test_ascii_login_still_changes_the_password(self):
        d, stub = self.daemon_and_stub(policy=BACKEND.replace("login backend = mavis", "login backend = mavis chpass"))
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH", "CHPW"])

    @unittest.skipUnless(shutil.which("perl"), "the backend is a Perl script")
    def test_expired_shadow_password(self):
        """lastchange 0 in the shadow file: the password has expired."""
        shadow = self.scratch_file("shadow", "alice:%s:0:0:99999:7:::\n" % crypt_md5("pw"))
        d = self.start_daemon("""
	mavis module = external {
		setenv SHADOWFILE = "%s"
		exec = "%s"
	}
""" % (shadow, SHADOW) + BACKEND.replace("login backend = mavis", "login backend = mavis chpass") + PERMIT)
        with d.connect() as c:
            r = c.pap("alice", "pw")
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "new").status_name, "PASS")



@unittest.skipUnless(shutil.which("perl"), "the backend is a Perl script")
class ShadowPasswordSalt(DaemonTestCase):
    """The salt of a changed password in mavis_tacplus_shadow.pl comes from /dev/urandom, not from Perl's rand().

    rand() is drand48() with a 32-bit seed: from a few salts in a shadow
    file the next ones follow. To show where the salt comes from, the
    backend runs with rand() seeded to the same value twice (PERL5OPT);
    with rand() both password changes get the same salt.
    """

    CONFIG = None

    def changed_hash(self, seed_dir, name):
        shadow = self.scratch_file(name, "alice:%s:0:0:99999:7:::\n" % crypt_md5("pw"))
        d = self.start_daemon("""
	mavis module = external {
		setenv SHADOWFILE = "%s"
		setenv PERL5OPT = "-I%s -MFixedSeed"
		exec = "%s"
	}
""" % (shadow, seed_dir, SHADOW) + BACKEND.replace("login backend = mavis", "login backend = mavis chpass") + PERMIT)
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        with open(shadow) as f:
            return f.read().split(":")[1]

    def test_salt_does_not_come_from_rand(self):
        seed_dir = os.path.dirname(self.scratch_file("FixedSeed.pm", "package FixedSeed;\nsrand(1);\n1;\n"))
        first, second = self.changed_hash(seed_dir, "shadow1"), self.changed_hash(seed_dir, "shadow2")
        self.assertTrue(first.startswith("$1$") and second.startswith("$1$"), (first, second))
        self.assertNotEqual(first.split("$")[2], second.split("$")[2], "the same salt twice: it comes from rand()")

class ProfileConflict(DaemonTestCase):
    """The backend authenticates the user, but the profile it sends sets a password that is not "mavis".

    The daemon logged the conflict and set S_deny, but then permitted the
    login anyway.
    """

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def test_profile_with_its_own_password_fails(self):
        Stub(self.daemon).set(users={"alice": {"password": "pw", "profile": "{ password pap = clear other }"}})
        self.assertEqual(self.connect().pap("alice", "pw").status_name, "FAIL")
        self.wait_log("authentication", "pap login failed")

    def test_cached_profile_password_does_not_log_in(self):
        """With a cache timeout, the refused user was cached with the clear text password of its profile."""
        d = self.start_daemon(self.CONFIG, template=config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = 60"))
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw", "profile": "{ password pap = clear other }"}})
        for password in ("pw", "other"):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, "FAIL")
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("AUTH", "ACK"), ("AUTH", "NAK")])

    def test_profile_password_does_not_log_in_in_the_same_session(self):
        """The refused user stayed in the session, so the next attempt checked the password of its profile."""
        for timeout in (0, 60):
            template = config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = %d" % timeout)
            d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + "\tpassword max-attempts = 3\n" + PERMIT,
                                  template=template)
            stub = Stub(d)
            stub.set(users={"alice": {"password": "pw", "profile": "{ password login = clear other }"}})
            with self.subTest(timeout=timeout), d.connect() as c:
                r = c.ascii_login("alice", ["pw", "other", "other"])
                self.assertEqual(r.statuses, ["GETPASS", "GETPASS", "GETPASS", "FAIL"], r)
                # each attempt goes to the backend
                self.assertEqual([e["result"] for e in stub.requests(type="AUTH")], ["ACK", "NAK", "NAK"])


@unittest.skipUnless(LINUX and "address" in sanitizers(), "LeakSanitizer needs an AddressSanitizer build on Linux")
class MavisAnswerFreed(DaemonTestCase):
    """mavis_switch() and mavis_dacl_switch() freed the MAVIS answer only when a user took it, mavis_ctx_switch() never."""

    CONFIG = None

    def start(self, policy, **kw):
        # the slow unwinder finds av_new() in the stack through the module
        with mock.patch.dict(os.environ, {"ASAN_OPTIONS": "detect_leaks=1:fast_unwind_on_malloc=0"}):
            return self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + policy + PERMIT, check=False, **kw)

    def worker(self, d):
        """The one worker, as (pid, starttime): leaked_answers() checks that the same process ends."""
        (worker,) = d.workers().items()
        return worker

    def leaked_answers(self, d, worker):
        """The LeakSanitizer reports of av_new() of the worker, after it exits."""
        self.assertEqual(self.worker(d), worker)
        pid, start = worker
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 30
        while daemon_alive(pid, start) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(daemon_alive(pid, start), "worker %d did not exit" % pid)
        report = ""
        for path in glob.glob(os.path.join(d.tmp, "*san.%d" % pid)):
            with open(path) as f:
                report += f.read()
        # the configuration pools always leak: a complete, symbolized report has them
        for text in ("ERROR: LeakSanitizer", " in main ", "SUMMARY: AddressSanitizer"):
            self.assertIn(text, report)
        return [b for b in re.split(r"\n(?=(?:Direct|Indirect) leak)", report) if " in av_new " in b]

    def test_refused_logins_free_the_answer(self):
        d = self.start("")
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw", "mustchange": True}, "bob": {"password": "pw"}})
        worker = self.worker(d)
        for user, password in (("alice", "pw"), ("bob", "wrong"), ("nobody", "pw")):
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, "FAIL")
        self.assertEqual([e["result"] for e in stub.requests(type="AUTH")], ["ACK", "NAK", "NOTFOUND"])
        self.assertEqual(self.leaked_answers(d, worker), [])

    def test_host_lookups_free_the_answer(self):
        d = self.start("""
	device mavis6 {
		address = 127.0.0.6
		mavis backend = yes
	}
	user alice {
		password pap = clear alicepw
	}
""")
        stub = Stub(d)
        stub.set(hosts={"127.0.0.6": "{ key = hostkey }"})
        worker = self.worker(d)
        for _ in range(3):
            with d.connect(source="127.0.0.6", key="hostkey") as c:
                self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        self.assertEqual([e["result"] for e in stub.requests(type="HOST")], ["ACK", "ACK", "ACK"])
        self.assertEqual(self.leaked_answers(d, worker), [])

    def test_dacl_downloads_free_the_answer(self):
        d = self.start("""
	include = "%s"
	device radius-nas {
		address = %s
		radius.key = %s
	}
""" % (os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg"), DACL_NAS, DACL_SECRET))
        stub = Stub(d)
        stub.set(dacls={"demoacl": '{ data = "%s" }' % DACL_ACE})
        worker = self.worker(d)
        event = b"aaa:event=acl-download"
        # RADIUS/TCP: the context ends with the connection, a UDP context lives for at least 60 s
        c = self.radius(DACL_SECRET, daemon=d, source=DACL_NAS, tcp=True)
        for name in ("demoacl", "demoacl", "unknown"):
            r = c.access_request("#ACSACL#%s-00000000" % name, "", message_authenticator=True,
                                 attributes=[(VENDOR_SPECIFIC, struct.pack("!IBB", CISCO_VENDOR, 1, len(event) + 2) + event)])
            with self.subTest(name=name):
                self.assertEqual(r.code_name, "Access-Accept" if name == "demoacl" else "Access-Reject", r)
        c.close()
        self.assertEqual([e["result"] for e in stub.requests(type="DACL")], ["ACK", "ACK", "NOTFOUND"])
        self.assertEqual(self.leaked_answers(d, worker), [])


def crypt_md5(password):
    """An MD5-crypt hash from the crypt() of Perl (the crypt module of Python is gone in 3.13)."""
    return subprocess.run(["perl", "-e", "print crypt($ARGV[0], q($1$tactest$))", password],
                          check=True, capture_output=True, text=True).stdout


def cpu_seconds(pid):
    """utime + stime of a process (Linux)."""
    with open("/proc/%d/stat" % pid) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


class Children(DaemonTestCase):
    """MAVIS children that die or misbehave; one child, so the stub's request counter is the child's."""

    CONFIG = None
    POLICY = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def daemon_and_stub(self, check=True, **state):
        d = self.start_daemon(self.POLICY, check=check)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, **state)
        return d, stub

    def forget_children(self, d):
        """The test killed MAVIS children on purpose: take the process set anew, keep the rest of the checks."""
        d.baseline = detect.Baseline(d, since=d.baseline)

    def test_child_exits_on_the_second_request(self):
        """The request a dying child took is sent to a new child."""
        d, stub = self.daemon_and_stub(exit=2)
        for _ in range(3):
            with d.connect() as c:
                self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        self.forget_children(d)
        children = [(e["n"], e["result"]) for e in stub.requests()]
        self.assertEqual(children, [(1, "ACK"), (2, "exit"), (1, "ACK"), (2, "exit"), (1, "ACK")])
        self.assertEqual(len({e["pid"] for e in stub.requests()}), 3)

    @unittest.skipUnless(LINUX, "CPU time from /proc")
    def test_issue197_no_busy_loop_after_a_child_quit(self):
        """#197: after a child of the external module quit, the worker kept polling its closed pipe at 100% CPU.

        The child quits after it answered its second request (a backend
        without a request loop quits after the first; the daemon handles a
        child that dies before its second request otherwise). It quits
        once the client has the answer: the answer of a child that exits
        right after writing it is occasionally lost, which is not what
        this test is about.
        """
        d, stub = self.daemon_and_stub(quit=2)
        (worker,) = d.workers()
        for _ in range(2):
            with d.connect() as c:
                self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        stub.release(2)
        child = stub.requests()[-1]["pid"]
        deadline = time.monotonic() + 5
        while daemon_alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(daemon_alive(child), "the child didn't quit")
        self.forget_children(d)
        before = cpu_seconds(worker)
        time.sleep(2)
        self.assertLess(cpu_seconds(worker) - before, 0.5)

    def test_issue228_demo_backend_answers_once(self):
        """#228: mavis_tacplus_demo.py wrote a second answer after is_tacplus()/valid() had answered."""
        demo = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_demo.py")
        env = dict(os.environ, PYTHONPATH=os.path.dirname(demo))
        for request in ("0 TACPLUS\n4 demo\n49 AUTH\n=\n",        # no password: valid() answers
                        "0 FTP\n4 demo\n8 demo\n49 AUTH\n=\n",   # not TACACS+: is_tacplus() answers
                        "0 TACPLUS\n4 demo\n8 demo\n49 AUTH\n=\n"):
            with self.subTest(request=request):
                out = subprocess.run([sys.executable, demo], input=request.encode(), stdout=subprocess.PIPE,
                                     timeout=30, env=env).stdout.decode()
                self.assertEqual(len([line for line in out.splitlines() if line.startswith("=")]), 1, out)

    def test_issue145_cache_directory_not_writable(self):
        """#145: tacinfo_cache and tacauth_limit dereferenced NULL when they couldn't write to their directory."""
        for module in ("tacinfo_cache", "tacauth_limit"):
            with self.subTest(module=module):
                body = "\tmavis module = %s { directory = /proc/tactest-not-writable }\n" % module + self.POLICY
                d = self.start_daemon(body, name=module)
                Stub(d).set(users={"alice": {"password": "pw"}})
                with d.connect() as c:
                    self.assertEqual(c.pap("alice", "pw").status_name, "PASS")


# Answers every request of the external-mt protocol with ACK and the profile from argv[1].
MT_BACKEND = r"""
import os, struct, sys

def exact(n):
    buf = b""
    while len(buf) < n:
        part = os.read(0, n - len(buf))
        if not part:
            sys.exit(0)
        buf += part
    return buf

with open(sys.argv[1]) as f:
    profile = f.read()
while True:
    magic, length, _ = struct.unpack("!III", exact(12))
    av = dict(line.split(" ", 1) for line in exact(length).decode().split("\n") if line)
    av["6"], av["48"] = "ACK", profile
    out = ("".join("%s %s\n" % kv for kv in av.items()) + "\n").encode()
    out = struct.pack("!III", magic, len(out), 0) + out
    while out:
        out = out[os.write(1, out):]
"""


@unittest.skipUnless(os.path.exists(os.path.join(prefix(), "lib", "mavis", "libmavis_external-mt.so")),
                     "configure builds external-mt only if it finds pthread")
class MtBackend(DaemonTestCase):
    """The external-mt module, with a backend that speaks its protocol."""

    CONFIG = None

    def login_with_profile(self, text):
        backend, profile = self.scratch_file("backend.py", MT_BACKEND), self.scratch_file("profile", text)
        d = self.start_daemon("""
	mavis module = external-mt {
		exec = "%s" "%s" "-u" "%s" "%s"
	}
""" % (sys.executable, sys.executable, backend, profile) + BACKEND + """
	group admins { }
	profile admin {
		script { if (service == shell) { set priv-lvl = 15 permit } }
	}
	ruleset {
		rule admins {
			script { if (member == admins) { profile = admin permit } }
		}
	}
""")
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        with d.connect() as c:
            r = c.author("alice", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))

    def test_login_uses_the_profile_of_the_backend(self):
        """The sanitizer builds catch the use of the freed serial of the request."""
        self.login_with_profile("{ member = admins }")

    def test_profile_above_the_limit_of_the_external_module(self):
        """external-mt can deliver a profile that the 66536 bytes reply buffer of external can't hold."""
        self.login_with_profile("{" + " " * 140000 + "member = admins }")

    def test_profile_larger_than_the_stack(self):
        """16 MB is above the stack limit of 8 MB set here; a stack buffer of that size killed the worker."""
        soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
        limit = 8 * 1024 * 1024 if hard == resource.RLIM_INFINITY else min(8 * 1024 * 1024, hard)
        resource.setrlimit(resource.RLIMIT_STACK, (limit, hard))
        self.addCleanup(resource.setrlimit, resource.RLIMIT_STACK, (soft, hard))
        self.login_with_profile("{" + " " * 16000000 + "member = admins }")


BACKEND_TIMEOUT = 60
MAVIS_DOWN = 16              # mavis/mavis.h
# below the large replies; glibc gives a thread the stack limit of the process
BACKEND_STACK = 8 * 1024 * 1024


def limit_stack():
    hard = resource.getrlimit(resource.RLIMIT_STACK)[1]
    soft = BACKEND_STACK if hard == resource.RLIM_INFINITY else min(BACKEND_STACK, hard)
    resource.setrlimit(resource.RLIMIT_STACK, (soft, hard))


def read_framed(out):
    """Return the body and the result from the header."""
    header = out.read(12)
    if len(header) != 12:
        return b"", None
    _, length, result = struct.unpack("!III", header)
    return out.read(length), result


def read_legacy(out):
    """The legacy reply ends with the result line "=<result>"."""
    lines = []
    for line in iter(out.readline, b""):
        lines.append(line)
        if line.startswith(b"="):
            break
    return b"".join(lines)


def backend_built(name):
    """configure found the library of the backend: the installation has the backend, its -mt variant, or both.

    With only the backend, the -mt variant is missing because configure found no pthreads, and the test fails.
    """
    return any(os.path.exists(os.path.join(prefix(), "sbin", n)) for n in (name, name + "-mt"))


class MtWorker(unittest.TestCase):
    """The real -mt backends, through the external-mt protocol. They need no server: a worker thread writes the reply."""

    def exchange(self, name, body, args=(), env=None, legacy=False, result=None):
        """Send one request and return the reply. With legacy, the request has no header.

        With result, the result in the header of a framed reply must be that value.
        """
        path = os.path.join(prefix(), "sbin", name)
        self.assertTrue(os.path.exists(path), "configure found the library, but no pthreads")
        request = body + b"=\n" if legacy else struct.pack("!III", 0x4d610001, len(body), 0) + body
        with subprocess.Popen([path, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env={**sanitizer_env(), **(env or {})}, preexec_fn=limit_stack) as p:
            # a hung backend fails the test, it does not block the run
            watchdog = threading.Timer(BACKEND_TIMEOUT, p.kill)
            watchdog.start()
            try:
                p.stdin.write(request)
                p.stdin.flush()
                reply, header_result = (read_legacy(p.stdout), None) if legacy else read_framed(p.stdout)
            finally:
                watchdog.cancel()
                p.kill()
        self.assertTrue(reply, "no reply, exit status %s" % p.returncode)
        if result is not None and not legacy:
            self.assertEqual(header_result, result)
        return reply

    def round_trip(self, name, size, args=(), env=None, legacy=False):
        """With legacy, the request has no header and the main thread answers."""
        value = b"x" * size
        # an existing user makes pammavis-mt start a thread, which writes the reply
        user = pwd.getpwuid(os.getuid()).pw_name.encode()
        body = b"4 " + user + b"\n8 pw\n21 serial\n49 AUTH\n32 " + value + b"\n"
        reply = self.exchange(name, body if legacy else body + b"\n", args, env, legacy)
        self.assertIn(b"21 serial\n", reply)
        self.assertTrue(value in reply, "the reply lost the value")
        self.assertFalse(re.search(rb"(?m)^17 \w+\(\): ", reply), "the main thread answered: no worker thread started")
        if legacy:
            self.assertRegex(reply, rb"\n=\d+\n\Z")
        return reply


@unittest.skipUnless(backend_built("pammavis"), "the build has no PAM backends")
class PamMtBackend(MtWorker):
    """pammavis-mt. No PAM service is necessary, the answer is a NAK."""

    def round_trip_pam(self, size, legacy=False):
        reply = self.round_trip("pammavis-mt", size, legacy=legacy)
        self.assertTrue(b"\n6 ACK\n" in reply or b"\n6 NAK\n" in reply, "no PAM result")

    def test_reply_above_the_default_thread_stack_of_musl(self):
        self.round_trip_pam(1000000)

    def test_reply_above_the_thread_stack(self):
        """The reply must not go on the stack of the worker thread, which has 8 MB."""
        self.round_trip_pam(16000000)

    def test_legacy_protocol(self):
        self.round_trip_pam(1000, legacy=True)

    def test_short_attributes_before_attribute_10(self):
        """av_array_to_char_len() took the digits of the attribute number from the length so far, not the number."""
        # no tactype: the main thread answers MAVIS_DOWN. A legacy request needs 12 bytes, the size of the header.
        body = b"4 u\n10 a\n21 s\n"
        for legacy, reply in ((False, body), (True, body + b"=16\n")):
            with self.subTest(legacy=legacy):
                self.assertEqual(self.exchange("pammavis-mt", body, legacy=legacy, result=MAVIS_DOWN), reply)


@unittest.skipUnless(os.path.exists(os.path.join(prefix(), "sbin", "ldapmavis-mt")), "the build has no LDAP backend")
class LdapMtBackend(MtWorker):
    """ldapmavis-mt without a server. The worker thread answers with the connection error."""

    def round_trip_ldap(self, size, legacy=False):
        self.round_trip("ldapmavis-mt", size, env={"LDAP_HOSTS": "ldap://127.0.0.1:1", "LDAP_BASE": "dc=example"},
                        legacy=legacy)

    def test_reply_above_the_default_thread_stack_of_musl(self):
        self.round_trip_ldap(1000000)

    def test_reply_above_the_thread_stack(self):
        self.round_trip_ldap(16000000)

    def test_legacy_protocol(self):
        self.round_trip_ldap(1000, legacy=True)


@unittest.skipUnless(backend_built("radmavis"), "the build has no RADIUS backend")
class RadiusMtBackend(MtWorker):
    """radmavis-mt without a server."""

    CONFIG = """
nas-identifier tactest
authserver 127.0.0.1:1:secret
acctserver 127.0.0.1:1:secret
dictionary /etc/radcli/dictionary
seqfile %s/seq
mapfile /dev/null
auth_order radius
login_tries 1
radius_timeout 1
radius_retries 1
serv-type udp
"""

    def round_trip_radius(self, size, legacy=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "radiusclient.conf")
            with open(path, "w") as f:
                f.write(self.CONFIG % tmp)
            self.round_trip("radmavis-mt", size, args=["-c", path], legacy=legacy)

    def test_reply_above_the_default_thread_stack_of_musl(self):
        self.round_trip_radius(1000000)

    def test_reply_above_the_thread_stack(self):
        self.round_trip_radius(16000000)

    def test_legacy_protocol(self):
        self.round_trip_radius(1000, legacy=True)


class ConfigurePthread(unittest.TestCase):
    """configure must find the same pthread support whatever the path of the temporary directory is."""

    def finds_pthread(self, name):
        source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "configure")
        with tempfile.TemporaryDirectory() as top:
            tmp = os.path.join(top, name)
            os.mkdir(tmp)
            os.makedirs(os.path.join(top, "spawnd", "perl"))  # configure writes a file there
            shutil.copy(source, top)
            subprocess.run(["./configure"], cwd=top, env={**os.environ, "TMPDIR": tmp}, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (makefile,) = glob.glob(os.path.join(top, "build", "Makefile.inc.*"))
            with open(makefile) as f:
                return "WITH_PTHREAD=1" in f.read()

    def test_tmpdir_with_special_characters(self):
        expected = self.finds_pthread("plain")
        if LINUX:
            self.assertTrue(expected, "configure found no pthread support, glibc and musl have it")
        for name in ("with space", "with'quote"):
            with self.subTest(name):
                self.assertEqual(self.finds_pthread(name), expected)



# Cisco type 6 values under the key "demo": "alicepw" and "naskey" (with a "\" that escape processing would drop)
TYPE6_ALICEPW = r"g^^PIBaDAZOHeG^fIU^eY_RUPZ`^]X"
TYPE6_NASKEY = r"KIXTPG^HRJ]FIdaO\IN]fRbFKaTAAB"
# "alicepw" again; in quotes with escape processing, its last "\" would escape the closing quote
TYPE6_ALICEPW_BACKSLASH = "MSdDeYGRL]eJ^CdYFR^IdeeiSRiIV\\"


# the startup message for a setenv value that has the form of a type 6 value but does not decrypt
WRONG_KEY = "the value has the form of a type 6 value, but it does not decrypt with the type6-key. The value is used as written."
NO_KEY = "the value has the form of a type 6 value, but no type6-key applies. The value is used as written."
# the messages of the start go to syslog, and with a debug mask also to stderr
DEBUG_MAVIS = 1 << 19


def startup_messages(d):
    with open(d.stderr_path) as f:
        return f.read()


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
class SetenvType6(DaemonTestCase):
    """"setenv" of the external module: the realm's final type6-key decrypts the value when the module starts.

    A value that does not decrypt goes to the child as written, with the normal escape processing.
    If it has the form of a type 6 value, the start logs a warning with its file and line.
    """

    CONFIG = None

    def module(self, value, plain=None):
        setenv = {"TACTEST_SECRET": "'%s'" % value}
        if plain is not None:
            setenv["TACTEST_PLAIN"] = "'%s'" % plain
        return Stub.module(childs=(1, 1), setenv=setenv) + BACKEND + PERMIT

    def child_env(self, d, listener=None):
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, env=["TACTEST_SECRET", "TACTEST_PLAIN"])
        with d.connect(listener=listener) as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        return stub.requests(type="AUTH")[-1]["env"]

    def child_value(self, d, listener=None):
        return self.child_env(d, listener)["TACTEST_SECRET"]

    def reports(self, d):
        """The startup messages about TACTEST_SECRET, each with the file and line of its setenv."""
        with open(d.cfg) as f:
            line = next(n for n, text in enumerate(f, 1) if "setenv TACTEST_SECRET" in text)
        log = startup_messages(d)
        prefix = "%s:%d: setenv TACTEST_SECRET: " % (d.cfg, line)
        return [text.split(prefix, 1)[1] for text in log.splitlines() if prefix in text]

    def test_key_after_the_module(self):
        d = self.start_daemon(self.module(TYPE6_ALICEPW) + "\ttype6-key = demo\n")
        self.assertEqual(self.child_value(d), "alicepw")

    def test_value_with_a_backslash(self):
        d = self.start_daemon("\ttype6-key = demo\n" + self.module(TYPE6_NASKEY))
        self.assertEqual(self.child_value(d), "naskey")

    def test_key_inherited_from_the_parent_realm(self):
        d = self.start_daemon("\ttype6-key = demo\n\trealm lab {\n" + self.module(TYPE6_ALICEPW) + "\t}\n",
                              listen={"lab": "realm = lab"})
        self.assertEqual(self.child_value(d, "lab"), "alicepw")

    def test_key_of_the_parent_of_a_sibling_parent_realm(self):
        """Realms complete in name order, so "a" completes before its parent "z" inherits the key."""
        d = self.start_daemon("\trealm z {\n\t}\n\trealm a {\n\t\tparent = z\n" + self.module(TYPE6_ALICEPW)
                              + "\t}\n\ttype6-key = demo\n", listen={"a": "realm = a"}, debug=DEBUG_MAVIS)
        self.assertEqual(self.child_value(d, "a"), "alicepw")
        self.assertEqual(self.reports(d), [])

    def test_each_realm_uses_its_own_key(self):
        realms = (("a", "\t\ttype6-key = demo\n", "alicepw"),
                  ("b", "", TYPE6_ALICEPW),
                  ("c", "\t\ttype6-key = other\n", TYPE6_ALICEPW))
        body = "".join("\trealm %s {\n%s%s\t}\n" % (name, key, self.module(TYPE6_ALICEPW)) for name, key, _ in realms)
        d = self.start_daemon(body, listen={name: "realm = %s" % name for name, _, _ in realms})
        for name, _, expected in realms:
            with self.subTest(realm=name):
                self.assertEqual(self.child_value(d, name), expected)

    def test_value_that_is_not_type6(self):
        d = self.start_daemon("\ttype6-key = demo\n" + self.module(r"plain\tvalue"), debug=DEBUG_MAVIS)
        self.assertEqual(self.child_value(d), "plain\tvalue")
        self.assertEqual(self.reports(d), [])

    def test_type6_value_with_a_wrong_key_is_reported(self):
        d = self.start_daemon("\ttype6-key = other\n" + self.module(TYPE6_ALICEPW), debug=DEBUG_MAVIS)
        self.assertEqual(self.child_value(d), TYPE6_ALICEPW)
        self.assertEqual(set(self.reports(d)), {WRONG_KEY})

    def test_type6_value_without_a_key_is_reported(self):
        d = self.start_daemon(self.module(TYPE6_ALICEPW), debug=DEBUG_MAVIS)
        self.assertEqual(self.child_value(d), TYPE6_ALICEPW)
        self.assertEqual(set(self.reports(d)), {NO_KEY})

    def test_value_that_ends_with_a_backslash(self):
        d = self.start_daemon("\ttype6-key = demo\n" + self.module(TYPE6_ALICEPW_BACKSLASH, "next"))
        self.assertEqual(self.child_env(d), {"TACTEST_SECRET": "alicepw", "TACTEST_PLAIN": "next"})

    def test_value_with_an_escaped_quote(self):
        d = self.start_daemon("\ttype6-key = demo\n" + self.module(r"it\'s", "next"))
        self.assertEqual(self.child_env(d), {"TACTEST_SECRET": "it's", "TACTEST_PLAIN": "next"})

    def test_short_value_of_type6_letters_with_an_escaped_quote(self):
        """Read without escape processing, "AB\\" would be a token of type 6 letters and the quote would end the string."""
        d = self.start_daemon("\ttype6-key = demo\n" + self.module(r"AB\'C", "next"))
        self.assertEqual(self.child_env(d), {"TACTEST_SECRET": "AB'C", "TACTEST_PLAIN": "next"})

    def test_long_value_of_type6_letters_with_an_escaped_quote(self):
        """Without escape processing, the 20 "A" and the "\\" would pass a check of the base41 format."""
        d = self.start_daemon("\ttype6-key = demo\n" + self.module("A" * 20 + r"\'C", "next"))
        self.assertEqual(self.child_env(d), {"TACTEST_SECRET": "A" * 20 + "'C", "TACTEST_PLAIN": "next"})

    def test_short_value_of_type6_letters_with_an_escape(self):
        d = self.start_daemon("\ttype6-key = demo\n" + self.module(r"AA\bAA"))
        self.assertEqual(self.child_value(d), "AA\bAA")

    def test_key_after_the_module_and_a_value_that_continues_after_an_escaped_quote(self):
        """Without escape processing, the value would end at the quote, with a valid type 6 value before it."""
        d = self.start_daemon(self.module(TYPE6_ALICEPW_BACKSLASH + "'C", "next") + "\ttype6-key = demo\n")
        self.assertEqual(self.child_env(d), {"TACTEST_SECRET": TYPE6_ALICEPW_BACKSLASH[:-1] + "'C", "TACTEST_PLAIN": "next"})


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
@unittest.skipUnless(os.path.exists(os.path.join(prefix(), "lib", "mavis", "libmavis_external-mt.so")),
                     "configure builds external-mt only if it finds pthread")
class SetenvType6Mt(DaemonTestCase):
    """"setenv" of the external-mt module."""

    CONFIG = None

    def child_env(self, value, key_first=False, key="demo"):
        key = "\ttype6-key = %s\n" % key
        profile = self.scratch_file("profile", "{ }")
        dump = profile + ".env"
        backend = self.scratch_file("backend.py", "import json, os, sys\nwith open(sys.argv[2], 'w') as f:\n"
                                    "    json.dump({k: v for k, v in os.environ.items() if k.startswith('TACTEST_')}, f)\n"
                                    + MT_BACKEND)
        d = self.start_daemon((key if key_first else "") + """
	mavis module = external-mt {
		exec = "%s" "%s" "-u" "%s" "%s" "%s"
		setenv TACTEST_SECRET = '%s'
		setenv TACTEST_PLAIN = 'next'
	}
""" % (sys.executable, sys.executable, backend, profile, dump, value) + ("" if key_first else key) + BACKEND + PERMIT,
                              debug=DEBUG_MAVIS)
        self.started = d
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        with open(dump) as f:
            return json.load(f)

    def test_key_after_the_module(self):
        self.assertEqual(self.child_env(TYPE6_ALICEPW), {"TACTEST_SECRET": "alicepw", "TACTEST_PLAIN": "next"})

    def test_value_that_ends_with_a_backslash(self):
        """The parser reads the value as written only if it decrypts with the key known at that time."""
        self.assertEqual(self.child_env(TYPE6_ALICEPW_BACKSLASH, key_first=True),
                         {"TACTEST_SECRET": "alicepw", "TACTEST_PLAIN": "next"})

    def test_short_value_of_type6_letters_with_an_escaped_quote(self):
        self.assertEqual(self.child_env(r"AB\'C"), {"TACTEST_SECRET": "AB'C", "TACTEST_PLAIN": "next"})

    def test_key_after_the_module_and_a_value_that_continues_after_an_escaped_quote(self):
        self.assertEqual(self.child_env(TYPE6_ALICEPW_BACKSLASH + "'C"),
                         {"TACTEST_SECRET": TYPE6_ALICEPW_BACKSLASH[:-1] + "'C", "TACTEST_PLAIN": "next"})

    def test_type6_value_with_a_wrong_key_is_reported(self):
        self.assertEqual(self.child_env(TYPE6_ALICEPW, key="other"), {"TACTEST_SECRET": TYPE6_ALICEPW, "TACTEST_PLAIN": "next"})
        self.assertIn("setenv TACTEST_SECRET: " + WRONG_KEY, startup_messages(self.started))


if __name__ == "__main__":
    unittest.main()
