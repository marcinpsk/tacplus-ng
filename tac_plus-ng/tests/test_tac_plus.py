"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import os
import shutil
import subprocess
import unittest

from tactest import DaemonTestCase, Stub, config, prefix
from tactest.daemon import parse_only
from tactest.tacacs import AUTHEN_TYPE_ASCII

TAC_PLUS = os.access(os.path.join(prefix(), "sbin", "tac_plus"), os.X_OK)


@unittest.skipUnless(TAC_PLUS, "no tac_plus in the installation under test")
class TacPlusTestCase(DaemonTestCase):
    PROGRAM = "tac_plus"
    TEMPLATE = config.TAC_PLUS


class Smoke(TacPlusTestCase):
    """One request of each type gets a well-formed reply."""

    CONFIG = """
	user = alice {
		pap = clear alicepw
		service = shell { default command = permit }
	}
"""

    def test_pap(self):
        self.assertTrue(self.connect().pap("alice", "alicepw").ok)

    def test_author(self):
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)

    def test_acct(self):
        self.assertTrue(self.connect().acct("alice", ["task_id=1", "service=shell"]).ok)


def users(conditions):
    """One user per condition; its shell authorization passes only if the condition holds."""
    return "".join(f"\tuser = {name} {{ service = shell {{ script = {{ if ({cond}) permit deny }} }} }}\n"
                   for name, cond in conditions)


CONDITIONS = [
    ("acl-eq", "acl == trusted"),
    ("acl-ne", "acl != trusted"),
    ("acl-not-eq", "!(acl == trusted)"),
    ("time-always-eq", "time == always"),
    ("time-always-ne", "time != always"),
    ("time-never-eq", "time == never"),
    ("time-never-ne", "time != never"),
    # the ACLs below use the ACL syntax, not a script
    ("std-acl-eq", "acl == std-acl-eq"),
    ("std-acl-ne", "acl == std-acl-ne"),
    ("std-acl-not", "acl == std-acl-not"),
    ("std-time-eq", "acl == std-time-eq"),
    ("std-time-ne", "acl == std-time-ne"),
    ("std-time-not", "acl == std-time-not"),
]


class AclAndTimeNegation(TacPlusTestCase):
    """"acl != NAME" and "time != NAME" are the negation of "==", in scripts and in ACLs.

    The tac_plus-ng counterpart is AclAndTimeNegation in test_policy.py.
    """

    CONFIG = """
	acl = trusted { nac = 127.0.7.1 }
	timespec = always { "* * * * *" }
	timespec = never { "* * 30 2 *" }
	acl = std-acl-eq { acl == trusted }
	acl = std-acl-ne { acl != trusted }
	acl = std-acl-not { acl = not trusted }
	acl = std-time-eq { time == never }
	acl = std-time-ne { time != never }
	acl = std-time-not { time = not never }
""" + users(CONDITIONS)

    def holds(self, kind, rem_addr):
        """Names of the conditions of this kind that hold for a request with this rem_addr."""
        c = self.connect()
        return [name for name, _ in CONDITIONS if name.startswith(kind + "-")
                and c.author(name, ["service=shell", "cmd="], rem_addr=rem_addr).ok]

    def test_acl_ne_is_the_negation_of_acl_eq(self):
        self.assertEqual(self.holds("acl", "127.0.7.1"), ["acl-eq"])
        self.assertEqual(self.holds("acl", "127.0.7.2"), ["acl-ne", "acl-not-eq"])

    def test_time_ne_is_the_negation_of_time_eq(self):
        self.assertEqual(self.holds("time", "127.0.0.1"), ["time-always-eq", "time-never-ne"])

    def test_acl_ne_in_an_acl(self):
        self.assertEqual(self.holds("std-acl", "127.0.7.1"), ["std-acl-eq"])
        self.assertEqual(self.holds("std-acl", "127.0.7.2"), ["std-acl-ne", "std-acl-not"])

    def test_time_ne_in_an_acl(self):
        self.assertEqual(self.holds("std-time", "127.0.0.1"), ["std-time-ne", "std-time-not"])


class PerTestDaemon(TacPlusTestCase):
    """start_daemon() starts the PROGRAM of the class with its TEMPLATE."""

    CONFIG = None

    def test_start_daemon_runs_tac_plus(self):
        d = self.start_daemon("\tuser = alice { pap = clear alicepw }\n")
        self.assertTrue(self.connect(d).pap("alice", "alicepw").ok)


class BareExclmark(TacPlusTestCase):
    """A script "acl ! NAME" or "time ! NAME" is a syntax error, as in an ACL; "!=" negates.

    tac_plus -P, because a parse error in a user script does not stop a daemon under spawnd.
    """

    CONFIG = None

    def test_bare_exclmark_is_rejected(self):
        for cond, name in (("acl ! trusted", "trusted"), ("time ! always", "always")):
            with self.subTest(cond=cond):
                body = ('\tacl = trusted { nac = 127.0.7.1 }\n\ttimespec = always { "* * * * *" }\n'
                        + users([("u", cond)]))
                path = self.scratch_file("tac_plus.cfg", config.render(config.TAC_PLUS, body=body))
                code, out = parse_only(path, program="tac_plus")
                self.assertEqual(code, 78, out)
                self.assertIn("Expected '=', but got '%s'" % name, out)


MAVIS_BACKEND = """
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
"""

SHADOW = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_shadow.pl")


class MustChangeWithoutDialog(TacPlusTestCase):
    """The backend answers OK with PASSWORD_MUSTCHANGE to a login that has no dialog for a new password.

    Only ASCII login and CHPASS can change a password. tac_plus permitted
    the other logins. The tac_plus-ng counterpart is MustChangeWithoutDialog
    in test_mavis.py.
    """

    CONFIG = None
    MESSAGE = "Please change your password."

    def daemon_and_stub(self):
        d = self.start_daemon(Stub.module(childs=(1, 1)) + MAVIS_BACKEND)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw", "mustchange": True}}, message=self.MESSAGE)
        return d, stub

    def test_pap_fails(self):
        d, stub = self.daemon_and_stub()
        for _ in range(2):
            with d.connect() as c:
                r = c.pap("alice", "pw")
            self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("AUTH", "ACK"), ("AUTH", "ACK")])

    def test_ascii_login_with_the_password_in_start_fails(self):
        """The PAP-like ASCII login of IOS-XR (user and password in START) has no dialog either."""
        d, stub = self.daemon_and_stub()
        with d.connect() as c:
            r = c.session().start(user="alice", data="pw", authen_type=AUTHEN_TYPE_ASCII)
        self.assertEqual(r.status_name, "FAIL", r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH"])

    def test_ascii_login_still_changes_the_password(self):
        d, stub = self.daemon_and_stub()
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["pw", "new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH", "CHPW"])

    @unittest.skipUnless(shutil.which("perl"), "the backend is a Perl script")
    def test_expired_shadow_password(self):
        """lastchange 0 in the shadow file: the password has expired."""
        shadow = self.scratch_file("shadow", f"alice:{crypt_md5('pw')}:0:0:99999:7:::\n")
        d = self.start_daemon(f"""
	mavis module = external {{
		setenv SHADOWFILE = "{shadow}"
		exec = "{SHADOW}"
	}}
""" + MAVIS_BACKEND)
        with d.connect() as c:
            r = c.pap("alice", "pw")
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["pw", "new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "new").status_name, "PASS")


def crypt_md5(password):
    """An MD5-crypt hash from the crypt() of Perl (the crypt module of Python is gone in 3.13)."""
    return subprocess.run(["perl", "-e", "print crypt($ARGV[0], q($1$tactest$))", password],
                          check=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    unittest.main()
