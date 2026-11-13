"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import os
import time
import unittest

from tactest import DaemonTestCase, Stub, config, prefix
from tactest.daemon import parse_only
from tactest.tacacs import AUTHEN_TYPE_ASCII, Packet

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


PORT_CONDITIONS = [
    ("script-eq", "port == tty1"),
    ("script-ne", "port != tty1"),
    ("script-re", "port =~ tty1"),
    ("script-nre", "port !~ tty1"),
    # the ACLs below use the ACL syntax, not a script
    ("acl-re", "acl == acl-re"),
    ("acl-nre", "acl == acl-nre"),
    ("acl-regex", "acl == acl-regex"),
    ("acl-regex-not", "acl == acl-regex-not"),
    ("acl-realm-eq", "acl == acl-realm-eq"),
    ("acl-realm-regex", "acl == acl-realm-regex"),
    ("acl-realm-re", "acl == acl-realm-re"),
    ("acl-realm-nre", "acl == acl-realm-nre"),
]


class PortAndRealmOperators(TacPlusTestCase):
    """The port and realm operators of the TacCond and ACLExpr grammars (doc/tac_plus.html).

    The request uses the default realm.
    """

    CONFIG = """
	acl = acl-re { port =~ tty1 }
	acl = acl-nre { port !~ tty1 }
	acl = acl-regex { port regex = tty1 }
	acl = acl-regex-not { port regex = not tty1 }
	acl = acl-realm-eq { realm = default }
	acl = acl-realm-regex { realm regex = def }
	acl = acl-realm-re { realm =~ def }
	acl = acl-realm-nre { realm !~ def }
""" + users(PORT_CONDITIONS)

    def holds(self, port):
        c = self.connect()
        return [name for name, _ in PORT_CONDITIONS if c.author(name, ["service=shell", "cmd="], port=port).ok]

    def test_port_tty1(self):
        self.assertEqual(self.holds("tty1"), ["script-eq", "script-re", "acl-re", "acl-regex",
                                              "acl-realm-eq", "acl-realm-regex", "acl-realm-re"])

    def test_port_tty2(self):
        self.assertEqual(self.holds("tty2"), ["script-ne", "script-nre", "acl-nre", "acl-regex-not",
                                              "acl-realm-eq", "acl-realm-regex", "acl-realm-re"])


class DocScriptExample(TacPlusTestCase):
    """The "acl script" example of doc/tac_plus.html, with "nac ==" and "nac-name" as its grammar says."""

    CONFIG = r"""
	host = SomeHostName { address = 127.0.7.0/24 }
	acl script = myacl123 {
		if (nas == 1.2.3.4 || nac == SomeHostName || nac-name =~ /\\.example\\.com$$/) deny
		permit
	}
""" + users([("joe", "acl == myacl123")])

    def test_client_in_the_host_is_denied(self):
        self.assertEqual(self.connect().author("joe", ["service=shell", "cmd="], rem_addr="127.0.7.1").status_name, "FAIL")

    def test_other_client_is_permitted(self):
        self.assertTrue(self.connect().author("joe", ["service=shell", "cmd="], rem_addr="127.0.8.1").ok)


if __name__ == "__main__":
    unittest.main()
