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
import os
import pwd
import re
import resource
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from tactest import LINUX, SOURCE, DaemonTestCase, Stub, config, detect, features, prefix
from tactest.daemon import alive as daemon_alive, parse_only, sanitizer_env

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
        """ERROR without a fallback user is a FAIL for the client too (the log tells them apart)."""
        for result, status in (("ACK", "PASS"), ("NAK", "FAIL"), ("NOTFOUND", "FAIL"), ("ERROR", "FAIL")):
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
        # reject_conn() resets the connection before the client sends: the reset can come before connect() returns
        try:
            c = self.connect(source="127.0.0.7")
        except ConnectionResetError:
            return
        self.assertTrue(c.closed(), "the daemon accepted the host")


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


LIST_POLICY = BACKEND + r"""
	alias admins_alias { admins }
	group ops { }
	group admins { }
	group "a\"b" { }
	ruleset {
		rule blocked { script { if (memberof == "cn=blocked\\,x,dc=example") { deny } } }
		rule admins { script { if (member == admins) { motd banner = "admins\n" permit } } }
		rule quote { script { if (member == "a\"b") { motd banner = "quote\n" permit } } }
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
                             (r'"a\"b"', "quote\n"), ("'a\"b'", "quote\n"), (r'"op\\s"', "")):
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
        """A memberof deny rule matches a DN with an escaped comma."""
        for memberof in (r'"cn=blocked\,x,dc=example"', r'"cn=staff,dc=example","cn=blocked\,x,dc=example"'):
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
		groups filter = /^(ops|a.b|root)$$/
		memberof filter = /staff|,b,/
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
                                 ({"memberof": r'"cn=a\,b,dc=example"'}, "comma\n")):
            with self.subTest(attributes=attributes):
                stub.set(users={"bob": dict(password="pw", **attributes)})
                r = self.connect().ascii_login("bob", "pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd))


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


GROUP_DB = "TACTEST_GROUP_DB"
GROUP_GID = 4242


@unittest.skipUnless(LINUX and shutil.which("unshare"), "a user and mount namespace (Linux, unshare)")
@unittest.skipIf(os.environ.get(GROUP_DB), "runs only outside the namespace")
class GroupNameTheListCannotCarry(unittest.TestCase):
    """A name from "resolve gids" that MEMBEROF cannot carry (a backslash at the end) makes tac_plus-ng refuse the answer.

    The test runs GroupNameInNamespace in a user and mount namespace with a group database that has such a name.
    """

    def test_refused(self):
        probe = subprocess.run(["unshare", "--user", "--mount", "--map-root-user", "true"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=30, check=False)
        if probe.returncode:
            self.skipTest("no user and mount namespace here: " + probe.stdout.decode("utf-8", "replace").strip())
        tmp = tempfile.mkdtemp(prefix="tactest-group-")
        self.addCleanup(shutil.rmtree, tmp)
        db = os.path.join(tmp, "group")
        with open("/etc/group") as f, open(db, "w") as g:
            g.write(f.read() + "bs\\:x:%d:\n" % GROUP_GID)
        p = subprocess.run(["unshare", "--user", "--mount", "--map-root-user", "sh", "-c",
                            'mount --bind "$0" /etc/group && exec "$@"', db,
                            sys.executable, "-m", "unittest", "-v", "test_mavis.GroupNameInNamespace"],
                           cwd=os.path.dirname(os.path.abspath(__file__)), env=dict(os.environ, **{GROUP_DB: "1"}),
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
                           check=False)
        out = p.stdout.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, out)
        self.assertRegex(out, r"\nRan 1 test", out)


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


# answers ACK with TACMEMBER admins and a MEMBEROF that a deny rule matches, in a form the wire format cannot
# carry; argv[1]: "mt" for the framing of external-mt, argv[2]: the form
MALFORMED_BACKEND = r"""
import os, struct, sys

def exact(n):
    buf = b""
    while len(buf) < n:
        part = os.read(0, n - len(buf))
        if not part:
            sys.exit(0)
        buf += part
    return buf

def answer(lines):
    av = dict(line.split(b" ", 1) for line in lines if line)
    av[b"6"], av[b"47"] = b"ACK", b"admins"
    if sys.argv[2] == "nul":
        av[b"1"] = b'"cn=blocked,dc=example"\0'
    elif sys.argv[2] == "nul-in-timestamp":
        # the serial first: only what comes after the NUL is lost
        av = {b"21": av.pop(b"21"), **av}
        av[b"3"] += b"\0"
        av[b"1"] = b'"cn=blocked,dc=example"'
    elif sys.argv[2] == "line-break":
        av[b"1"] = b'"cn=other,dc=example",\n"cn=blocked,dc=example"'
    elif sys.argv[2] == "stray-equal":
        # a line that starts with "=" in the body is not an attribute; without it the list is well-formed
        av[b"1"] = b'"cn=other,dc=example"\n=0 "cn=blocked,dc=example"'
    body = b"".join(b"%s %s\n" % kv for kv in av.items())
    if sys.argv[2] == "no-final-lf":
        body += b'1 "cn=blocked,dc=example"'
    return body

if sys.argv[1] == "mt":
    while True:
        magic, length, _ = struct.unpack("!III", exact(12))
        out = answer(exact(length).split(b"\n"))
        out = struct.pack("!III", magic, len(out), 0) + out
        while out:
            out = out[os.write(1, out):]
else:
    lines = []
    for line in sys.stdin.buffer:
        if line == b"=\n":
            sys.stdout.buffer.write(answer(lines) + (b"\n" if sys.argv[2] == "no-final-lf" else b"") + b"=0\n")
            sys.stdout.buffer.flush()
            lines = []
        else:
            lines.append(line.rstrip(b"\n"))
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class MalformedAnswer(DaemonTestCase):
    """An answer that the wire format cannot carry is the request, refused: no part of it is used.

    It is not a backend error, so "authentication fallback" and "permit if-authenticated" do not authorize it.
    """

    CONFIG = None

    def start(self, module, mode, form):
        backend = self.scratch_file("backend.py", MALFORMED_BACKEND)
        return self.start_daemon("""
	mavis module = %s {
		exec = "%s" "%s" "-u" "%s" "%s" "%s"
	}
""" % (module, sys.executable, sys.executable, backend, mode, form) + BACKEND + """
	device trusting {
		address = 127.0.10.1
		key = tactest
		permit if-authenticated = yes
		authentication fallback = yes
	}
	group admins { }
	ruleset {
		rule blocked { script { if (memberof == "cn=blocked,dc=example") { deny } } }
		rule admins { script { if (member == admins) { permit } } }
	}
""")

    def check(self, module, mode, forms):
        for form in forms:
            with self.subTest(form=form):
                d = self.start(module, mode, form)
                with d.connect() as c:
                    self.assertEqual(c.pap("alice", "pw").status_name, "FAIL")
                r = d.connect(source="127.0.10.1").author("alice", ["service=shell", "cmd="], authen_method=5)
                self.assertEqual(r.status_name, "FAIL")

    def test_external(self):
        self.check("external", "plain", ("nul", "nul-in-timestamp", "line-break", "stray-equal"))

    @unittest.skipUnless(os.path.exists(os.path.join(prefix(), "lib", "mavis", "libmavis_external-mt.so")),
                         "configure builds external-mt only if it finds pthread")
    def test_external_mt(self):
        self.check("external-mt", "mt", ("nul", "nul-in-timestamp", "line-break", "stray-equal", "no-final-lf"))


# external-mt: the first child takes a small stdin pipe, waits until requests queue up behind it, then answers
# one without a serial; the next child answers each request; argv[1]: the marker file of the first child
RESTART_BACKEND = r"""
import fcntl, os, struct, sys, time

def exact(n):
    buf = b""
    while len(buf) < n:
        part = os.read(0, n - len(buf))
        if not part:
            sys.exit(0)
        buf += part
    return buf

first = not os.path.exists(sys.argv[1])
if first:
    open(sys.argv[1], "w").close()
    fcntl.fcntl(0, fcntl.F_SETPIPE_SZ, 4096)
    time.sleep(3)
while True:
    magic, length, _ = struct.unpack("!III", exact(12))
    av = dict(line.split(b" ", 1) for line in exact(length).split(b"\n") if line)
    if first:
        out = b"6 ACK\n"
    else:
        av[b"6"] = b"ACK"
        out = b"".join(b"%s %s\n" % kv for kv in av.items())
    out = struct.pack("!III", magic, len(out), 0) + out
    while out:
        out = out[os.write(1, out):]
"""


@unittest.skipUnless(LINUX, "F_SETPIPE_SZ is Linux only")
@unittest.skipUnless(os.path.exists(os.path.join(prefix(), "lib", "mavis", "libmavis_external-mt.so")),
                     "configure builds external-mt only if it finds pthread")
class ExternalMtRestartWithQueue(DaemonTestCase):
    """external-mt restarts a child that answers without a serial; the new child gets the requests that were queued."""

    CONFIG = None
    LOGINS = 40

    def test_queued_requests(self):
        backend = self.scratch_file("backend.py", RESTART_BACKEND)
        # check=False: the first child of the backend is killed on purpose
        d = self.start_daemon("""
	mavis module = external-mt {
		exec = "%s" "%s" "-u" "%s" "%s"
	}
""" % (sys.executable, sys.executable, backend, os.path.join(os.path.dirname(backend), "first")) + BACKEND + PERMIT,
                              check=False)
        results = []

        def login(i):
            with d.connect(timeout=30) as c:
                results.append(c.pap("user%d" % i, "pw").status_name)

        threads = [threading.Thread(target=login, args=(i,)) for i in range(self.LOGINS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, ["PASS"] * self.LOGINS)


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class MalformedRemoteAnswer(DaemonTestCase):
    """The remote module refuses a reply datagram that is not whole attribute lines, as external and external-mt do."""

    CONFIG = None

    def peer(self, last_line):
        """A MAVIS peer on UDP that answers ACK, TACMEMBER admins and a MEMBEROF of a deny rule, as last_line."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(65536)
                except socket.timeout:
                    continue
                av = dict(line.split(b" ", 1) for line in data.split(b"\n") if b" " in line)
                av[b"6"], av[b"47"] = b"ACK", b"admins"
                av.pop(b"1", None)
                sock.sendto(b"".join(b"%s %s\n" % kv for kv in av.items()) + last_line, addr)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.addCleanup(sock.close)
        self.addCleanup(t.join)
        self.addCleanup(stop.set)
        return sock.getsockname()[1]

    def test_truncated_reply(self):
        for name, last_line, status in (("whole", b'1 "cn=other,dc=example"\n', "PASS"),
                                        ("no final LF", b'1 "cn=blocked,dc=example"', "FAIL"),
                                        ("NUL", b'1 "cn=blocked,dc=example"\0\n', "FAIL")):
            with self.subTest(reply=name):
                d = self.start_daemon("""
	mavis module = remote {
		server { address = 127.0.0.1 port = %d }
		timeout = 2
		tries = 1
	}
""" % self.peer(last_line) + BACKEND + """
	group admins { }
	ruleset {
		rule blocked { script { if (memberof == "cn=blocked,dc=example") { deny } } }
		rule admins { script { if (member == admins) { permit } } }
	}
""")
                with d.connect() as c:
                    self.assertEqual(c.pap("alice", "pw").status_name, status)


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


if __name__ == "__main__":
    unittest.main()
