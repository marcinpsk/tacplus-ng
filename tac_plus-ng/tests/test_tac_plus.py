"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import os
import shutil
import subprocess
import time
import unittest

from tactest import DaemonTestCase, Stub, config, prefix
from tactest.daemon import parse_only
from tactest.tacacs import AUTHEN_SVC_ENABLE, AUTHEN_TYPE_ASCII, Packet

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
	user = bob {
		service = shell {
			default command = permit
			set priv-lvl = 15
		}
	}
"""

    def test_pap(self):
        self.assertTrue(self.connect().pap("alice", "alicepw").ok)

    def test_author(self):
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)

    def test_author_with_an_attribute(self):
        """The attribute trees of authorize_svc() call their compare function with the type of the tree."""
        r = self.connect().author("bob", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))

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


class SingleConnectionMayClose(TacPlusTestCase):
    """With single-connection may-close, the end of a session closes the connection; the context is freed once."""

    CONFIG = """
	session timeout = 30
	host = may-close {
		address = 127.0.0.1/32
		single-connection = yes
		single-connection may-close = yes
		password backoff = 1
	}
	user = alice {
		login = clear alicepw
		pap = clear alicepw
		service = shell { default command = permit }
	}
"""

    def login_in_progress(self, daemon=None):
        """A connection with an ASCII login that waits for the user name."""
        c = self.connect(daemon)
        s = c.session()
        self.assertEqual(s.start(authen_type=AUTHEN_TYPE_ASCII).status_name, "GETUSER")
        return c, s

    def test_a_reply_closes_the_connection(self):
        with self.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
            self.assertTrue(c.closed(), "the connection stays open after the reply")

    def test_an_authorization_reply_closes_the_connection(self):
        with self.connect() as c:
            self.assertEqual(c.author("alice", ["service=shell", "cmd="]).status_name, "PASS_ADD")
            self.assertTrue(c.closed(), "the connection stays open after the reply")

    def test_an_accounting_reply_closes_the_connection(self):
        with self.connect() as c:
            self.assertTrue(c.acct("alice", ["task_id=1", "service=shell"]).ok)
            self.assertTrue(c.closed(), "the connection stays open after the reply")

    def test_a_reply_from_mavis_comes_before_the_close(self):
        """The connection has no output while the daemon waits for the MAVIS answer."""
        backend = "\tuser backend = mavis\n\tpap backend = mavis\n"
        d = self.start_daemon(Stub.module(childs=(1, 1)) + backend + self.CONFIG)
        stub = Stub(d)
        stub.set(users={"bob": {"password": "bobpw"}})
        with d.connect() as c:
            self.assertEqual(c.pap("bob", "bobpw").status_name, "PASS")
            self.assertTrue(c.closed(), "the connection stays open after the reply")
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH"])

    def test_a_delayed_reply_comes_before_the_close(self):
        """password backoff delays the FAIL reply."""
        with self.connect() as c:
            start = time.monotonic()
            self.assertEqual(c.pap("alice", "wrong").status_name, "FAIL")
            self.assertGreaterEqual(time.monotonic() - start, 0.9, "the reply has no delay")
            self.assertTrue(c.closed(), "the connection stays open after the reply")

    def test_a_wrong_sequence_number_closes_the_connection(self):
        c, s = self.login_in_progress()
        c.send(Packet.authen_continue(user_msg="alice", seq_no=5, session_id=s.session_id))
        self.assertTrue(c.closed(), "the connection stays open")

    def test_an_abort_closes_the_connection(self):
        c, s = self.login_in_progress()
        s.cont(abort=True)
        self.assertTrue(c.closed(), "the connection stays open")

    def test_an_unknown_packet_type_closes_the_connection(self):
        with self.connect() as c:
            c.send(Packet(9, b"\0" * 8))
            self.assertTrue(c.closed(), "the connection stays open")

    def test_a_disconnect_in_an_ascii_login(self):
        c, _ = self.login_in_progress()
        c.close()
        with self.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")

    def test_the_periodic_task_closes_only_may_close_connections(self):
        """The periodic task of a connection runs 60 s after the connection opens.

        It ends the sessions that have timed out. With single-connection = no, a connection
        can have two sessions: the second has not timed out then. A single connection
        that the client asked for stays open after a reply, until the periodic task.
        A connection of a host with may-close = no stays open.
        """
        no_single = self.start_daemon(self.CONFIG.replace("single-connection = yes", "single-connection = no"))
        keep_open = self.start_daemon(self.CONFIG.replace("may-close = yes", "may-close = no"))
        keep = self.connect(keep_open)
        self.assertEqual(keep.pap("alice", "alicepw").status_name, "PASS")
        idle = self.connect(single_connect=True)
        self.assertEqual(idle.pap("alice", "alicepw").status_name, "PASS")
        self.assertFalse(idle.closed(timeout=1), "the single connection closes after the reply")
        c1, _ = self.login_in_progress()
        c2, _ = self.login_in_progress(no_single)
        time.sleep(35)
        self.assertEqual(c2.session().start(authen_type=AUTHEN_TYPE_ASCII).status_name, "GETUSER")
        self.assertTrue(c1.closed(timeout=35), "the connection stays open")
        self.assertTrue(c2.closed(timeout=35), "the connection with two sessions stays open")
        self.assertTrue(idle.closed(timeout=5), "the idle single connection stays open")
        self.assertFalse(keep.closed(timeout=1), "the connection of the may-close = no host closes")
        self.assertEqual(keep.pap("alice", "alicepw").status_name, "PASS")


class RealmSingleConnectionMayClose(TacPlusTestCase):
    """single-connection may-close set on the realm, not on a host, must reach the context.

    new_context() copies the realm settings to the context. The host hierarchy then
    overrides a setting that a matched host sets. Here no host sets may-close, so the
    realm value is the only source. A reply must close the connection.
    """

    CONFIG = """
	single-connection = yes
	single-connection may-close = yes
	user = alice {
		login = clear alicepw
		pap = clear alicepw
		service = shell { default command = permit }
	}
"""

    def test_a_realm_reply_closes_the_connection(self):
        with self.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
            self.assertTrue(c.closed(), "the connection stays open after the reply")


class SequenceNumber(TacPlusTestCase):
    """RFC 8907 4.1: the daemon ends the session at packet 255, it does not answer with sequence number 0."""

    CONFIG = """
	single-connection = yes
	password max-attempts = 200
	user = alice {
		login = clear alicepw
		pap = clear alicepw
	}
"""

    def test_the_sequence_number_does_not_wrap(self):
        with self.connect() as c:
            s = c.session()
            r = s.start(authen_type=AUTHEN_TYPE_ASCII)
            while s.seq_no < 254:
                self.assertEqual(r.status_name, "GETUSER", r)
                r = s.cont()
            s.send(Packet.authen_continue())
            self.assertTrue(c.silent(), "the daemon answered packet 255")

    def test_the_right_password_in_packet_255_does_not_pass(self):
        with self.connect() as c:
            s = c.session()
            r = s.start(user="alice", authen_type=AUTHEN_TYPE_ASCII)
            while s.seq_no < 254:
                self.assertEqual(r.status_name, "GETPASS", r)
                r = s.cont(user_msg="wrong%d" % s.seq_no)
            s.send(Packet.authen_continue(user_msg="alicepw"))
            self.assertTrue(c.silent(), "the daemon answered packet 255")

    def test_the_limit_with_single_connection_may_close(self):
        """The end of the last session closes the connection; the context is freed once."""
        d = self.start_daemon(self.CONFIG + "\thost = may-close { address = 127.0.0.1/32 single-connection may-close = yes }\n")
        with d.connect() as c:
            s = c.session()
            r = s.start(authen_type=AUTHEN_TYPE_ASCII)
            while s.seq_no < 254:
                r = s.cont()
            s.send(Packet.authen_continue())
            self.assertTrue(c.closed(), "the daemon answered packet 255")

    def test_other_sessions_on_a_single_connection_go_on(self):
        with self.connect(single_connect=True) as c:
            s = c.session()
            r = s.start(authen_type=AUTHEN_TYPE_ASCII)
            while s.seq_no < 254:
                r = s.cont()
            s.send(Packet.authen_continue())
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")

    def test_an_even_number_while_a_reply_is_due_ends_the_session(self):
        """A packet that the client sends before the reply to its previous packet."""
        d = self.start_daemon(Stub.module(childs=(1, 1)) + MAVIS_BACKEND)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, hold=1)
        with d.connect() as c:
            s = c.session()
            self.assertEqual(s.start(user="alice", authen_type=AUTHEN_TYPE_ASCII).status_name, "GETPASS")
            s.send(Packet.authen_continue(user_msg="pw"))
            deadline = time.monotonic() + 5
            while not stub.requests() and time.monotonic() < deadline:
                time.sleep(0.02)
            s.send(Packet.authen_continue(user_msg="pw"))
            time.sleep(0.5)
            stub.release(1)
            self.assertTrue(c.silent(), "the daemon answered")
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH"])


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
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("AUTH", "ACK")])

    def test_ascii_login_still_changes_the_password(self):
        d, stub = self.daemon_and_stub()
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["pw", "new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH", "CHPW"])

    def test_refused_answer_updates_the_cached_profile(self):
        """The profile of the refused answer replaces the cached profile and its cached PAP password."""
        d, stub = self.daemon_and_stub()
        stub.set(users={"alice": {"password": "pw", "profile": "{ service = shell { default command = permit } }"}})
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        stub.set(users={"alice": {"password": "pw", "mustchange": True,
                                  "profile": "{ service = shell { script = { deny } } }"}}, message=self.MESSAGE)
        with d.connect() as c:
            r = c.session().start(user="alice", data="pw", authen_type=AUTHEN_TYPE_ASCII)
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        with d.connect() as c:
            r = c.author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "FAIL", r)
        with d.connect() as c:
            r = c.pap("alice", "pw")
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("AUTH", "ACK")] * 3)

    def test_refused_answer_does_not_extend_the_cache(self):
        """A refused answer does not keep a cached PAP password valid after the cache timeout."""
        d = self.start_daemon(Stub.module(childs=(1, 1)) + "\tcache timeout = 11\n" + MAVIS_BACKEND)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}})
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        stub.set(users={"alice": {"password": "pw", "mustchange": True}}, message=self.MESSAGE)
        time.sleep(7)
        with d.connect() as c:
            r = c.session().start(user="alice", data="pw", authen_type=AUTHEN_TYPE_ASCII)
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        time.sleep(5.5)
        with d.connect() as c:
            r = c.pap("alice", "pw")
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("AUTH", "ACK")] * 3)

    def test_enable_gets_the_challenge_of_a_must_change_answer(self):
        """The refusal is for AUTH answers: a CHAL answer with PASSWORD_MUSTCHANGE still gives its challenge."""
        d = self.start_daemon(Stub.module(childs=(1, 1)) + MAVIS_BACKEND.replace("mavis chpass", "mavis chalresp chpass"))
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw", "mustchange": True, "challenge": "otp-md5 99 tactest",
                                  "profile": "{ enable = login }"}}, message=self.MESSAGE)
        with d.connect() as c:
            s = c.session()
            r = s.start(user="alice", authen_type=AUTHEN_TYPE_ASCII, service=AUTHEN_SVC_ENABLE, priv_lvl=15)
            self.assertEqual(r.status_name, "GETPASS", r)
            self.assertIn("otp-md5 99 tactest", r.server_msg, r)
            r = s.cont(user_msg="pw")
        self.assertEqual(r.status_name, "FAIL", r)
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()],
                         [("INFO", "ACK"), ("CHAL", "ACK"), ("AUTH", "ACK")])

    def test_authorization_uses_the_profile_of_an_info_answer(self):
        """An INFO answer with PASSWORD_MUSTCHANGE still gives the profile for authorization."""
        d, stub = self.daemon_and_stub()
        stub.set(users={"alice": {"password": "pw", "mustchange": True,
                                  "profile": "{ service = shell { default command = permit } }"}})
        with d.connect() as c:
            r = c.author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        self.assertEqual([(e["type"], e["result"]) for e in stub.requests()], [("INFO", "ACK")])

    def expired_shadow_daemon(self):
        """lastchange 0 in the shadow file: the password has expired."""
        if not shutil.which("perl"):
            self.skipTest("the backend is a Perl script")
        shadow = self.scratch_file("shadow", f"alice:{crypt_md5(self, 'pw')}:0:0:99999:7:::\n")
        return self.start_daemon(f"""
	mavis module = external {{
		setenv SHADOWFILE = "{shadow}"
		exec = "{SHADOW}"
	}}
""" + MAVIS_BACKEND)

    def test_expired_shadow_password(self):
        d = self.expired_shadow_daemon()
        with d.connect() as c:
            r = c.pap("alice", "pw")
        self.assertEqual((r.status_name, r.server_msg.strip()), ("FAIL", self.MESSAGE), r)
        with d.connect() as c:
            r = c.ascii_login("alice", "pw", data=["pw", "new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "new").status_name, "PASS")

    def test_chpass_changes_an_expired_shadow_password(self):
        """CHPASS START: the CHPW answer of the backend keeps PASSWORD_MUSTCHANGE."""
        d = self.expired_shadow_daemon()
        with d.connect() as c:
            s = c.session()
            r = s.dialog(s.start(user="alice", action=2, authen_type=AUTHEN_TYPE_ASCII),
                         {"GETDATA": ["pw"], "GETPASS": ["new", "new"]})
        self.assertEqual(r.statuses, ["GETDATA", "GETPASS", "GETPASS", "PASS"], r)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "new").status_name, "PASS")


def crypt_md5(test, password):
    """An MD5-crypt hash from the crypt() of Perl (the crypt module of Python is gone in 3.13)."""
    salt = "$1$tactest$"
    hashed = subprocess.run(["perl", "-e", "print crypt($ARGV[0], $ARGV[1])", password, salt],
                            check=True, capture_output=True, text=True).stdout
    if not hashed.startswith(salt):
        test.skipTest("the crypt() of the system has no MD5-crypt")
    return hashed


if __name__ == "__main__":
    unittest.main()
