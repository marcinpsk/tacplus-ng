"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import grp
import os
import shutil
import time
import unittest

from tactest import GROUP_DB, LINUX, DaemonTestCase, Stub, config, prefix, run_with_group_db
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
    return "".join("\tuser = %s { service = shell { script = { if (%s) permit deny } } }\n" % (name, cond)
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


class ModuleScriptOnMalformedList(TacPlusTestCase):
    """A module script with a deny rule and a malformed TACMEMBER: libmavis fails the answer, also for tac_plus."""

    CONFIG = Stub.module(childs=(1, 1), script=r"""
		script out {
			if ($$TACMEMBER =~ /blocked/) {
				set $$RESULT = NAK
				return
			}
		}""") + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	group = guest {
		service = shell { default command = permit }
	}
	group = blocked {
		service = shell { default command = permit }
	}
"""

    def author(self, user, member):
        Stub(self.daemon).set(users={user: {"password": "pw", "member": member}})
        return self.connect().author(user, ["service=shell", "cmd="]).status_name

    def test_deny_rule(self):
        self.assertEqual(self.author("carol", '"guest"'), "PASS_ADD")
        self.assertEqual(self.author("dave", '"guest","blocked"'), "FAIL")
        # a line break: the tac_plus parser takes it as a blank, the list decoder as malformed
        self.assertEqual(self.author("erin", '"guest",\n"blocked"'), "FAIL")


class GroupsFilterOnMalformedList(TacPlusTestCase):
    """The groups module and a malformed TACMEMBER: libmavis fails the answer, also for tac_plus."""

    CONFIG = """
	mavis module = groups {
		groups filter = /^guest$$/
	}
""" + Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	group = guest {
		service = shell { default command = permit }
	}
"""

    def test_filter(self):
        stub = Stub(self.daemon)
        stub.set(users={"carol": {"password": "pw", "member": '"guest","blocked"'}})
        self.assertEqual(self.connect().author("carol", ["service=shell", "cmd="]).status_name, "PASS_ADD")
        stub.set(users={"dave": {"password": "pw", "member": '"guest",\n"blocked"'}})
        self.assertEqual(self.connect().author("dave", ["service=shell", "cmd="]).status_name, "FAIL")


BACKSLASH_GID = 4243


@unittest.skipUnless(TAC_PLUS and LINUX and shutil.which("unshare"), "tac_plus, a user and mount namespace")
@unittest.skipIf(os.environ.get(GROUP_DB), "runs only outside the namespace")
class ResolvedGroupNameWithBackslash(unittest.TestCase):
    """"resolve gids attribute = TACMEMBER" and a group name with a backslash: tac_plus finds the group of that name.

    The test runs ResolvedGroupNameInNamespace in a user and mount namespace with a group database that has such a
    name.
    """

    def test_member(self):
        run_with_group_db(self, "ops\\team:x:%d:\n" % BACKSLASH_GID, "test_tac_plus.ResolvedGroupNameInNamespace")


@unittest.skipUnless(os.environ.get(GROUP_DB), "runs in the namespace of ResolvedGroupNameWithBackslash")
class ResolvedGroupNameInNamespace(TacPlusTestCase):
    CONFIG = None

    def test_author(self):
        self.assertEqual(grp.getgrgid(BACKSLASH_GID).gr_name, "ops\\team")
        for option in ("gid", "gids"):
            with self.subTest(option=option):
                d = self.start_daemon("""
	mavis module = groups {
		resolve %(option)s = yes
		resolve %(option)s attribute = TACMEMBER
	}
""" % {"option": option} + Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	group = ops\\team {
		service = shell { default command = permit }
	}
""", name="resolve-" + option)
                Stub(d).set(users={"bob": {"password": "pw", option: str(BACKSLASH_GID)}})
                self.assertEqual(self.connect(d).author("bob", ["service=shell", "cmd="]).status_name, "PASS_ADD")


class MavisListValues(TacPlusTestCase):
    """TACMEMBER and TACCLIENT of a backend: the list values of that one attribute, taken literally."""

    CONFIG = Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	group = admin {
		service = shell {
			default command = permit
			set priv-lvl = 15
		}
	}
	group = guest {
		service = shell {
			default command = permit
			set priv-lvl = 1
		}
	}
	group = "$${TACTEST_ENV_LITERAL}" {
		service = shell {
			default command = permit
			set priv-lvl = 7
		}
	}
	group = ops\\team {
		service = shell {
			default command = permit
			set priv-lvl = 3
		}
	}
"""

    @classmethod
    def setUpClass(cls):
        # the daemon gets the environment of the tests; the configuration replaces ${VAR}, so the group
        # "$${TACTEST_ENV_LITERAL}" (template text) has the literal name ${TACTEST_ENV_GROUP}
        for name, value in (("TACTEST_ENV_GROUP", "admin"), ("TACTEST_ENV_LITERAL", "${TACTEST_ENV_GROUP}")):
            os.environ[name] = value
            cls.addClassCleanup(os.environ.pop, name)
        super().setUpClass()

    count = 0

    def author(self, **attributes):
        """A user of its own for each request: the daemon keeps the users of the backend for a while."""
        MavisListValues.count += 1
        user = "user%d" % MavisListValues.count
        Stub(self.daemon).set(users={user: dict(password="pw", **attributes)})
        r = self.connect().author(user, ["service=shell", "cmd="])
        return r.status_name, r.args

    def test_list(self):
        self.assertEqual(self.author(member='"admin"'), ("PASS_ADD", ["priv-lvl=15"]))
        self.assertEqual(self.author(member="guest"), ("PASS_ADD", ["priv-lvl=1"]))

    def test_value_is_literal(self):
        """No ${VAR} in a value: the value names the group with the literal name."""
        self.assertEqual(self.author(member='"${TACTEST_ENV_GROUP}"'), ("PASS_ADD", ["priv-lvl=7"]))

    def test_backslash_in_quotes(self):
        """A backslash in double quotes is part of the value, as av_add_quoted() and quote_list() write it."""
        self.assertEqual(self.author(member='"ops\\team"'), ("PASS_ADD", ["priv-lvl=3"]))

    def pap(self, client, rem_addr):
        MavisListValues.count += 1
        user = "user%d" % MavisListValues.count
        Stub(self.daemon).set(users={user: {"password": "pw", "client": client}})
        return self.connect().pap(user, "pw", rem_addr=rem_addr).status_name

    def test_client_keyword(self):
        """TACCLIENT: a blank or a tab after "deny", as the configuration tokenizer reads them."""
        for client in ("deny 10.0.0.0/8,0.0.0.0/0", "deny\t10.0.0.0/8,0.0.0.0/0", '"deny\t10.0.0.0/8","0.0.0.0/0"'):
            with self.subTest(client=client):
                self.assertEqual(self.pap(client, "10.1.2.3"), "FAIL")
                self.assertEqual(self.pap(client, "192.0.2.1"), "PASS")

    def test_prefix_length_is_a_number(self):
        """An empty prefix length, or text after it, is a profile error: before, "/" alone matched every IPv4 address."""
        for member in ('"admin@10.0.0.0/"', '"admin@10.0.0.0/ bogus"', 'admin@10.0.0.0/8 bogus', '"admin@::/ bogus"'):
            with self.subTest(member=member):
                self.assertEqual(self.author(member=member)[0], "ERROR")
        self.assertEqual(self.author(member='"admin@127.0.0.0/8"'), ("PASS_ADD", ["priv-lvl=15"]))

    def test_value_has_only_entries_of_its_attribute(self):
        """Text after the list is a parse error: no authorization."""
        for member in ('"guest" member = admin', '"guest" }', '"guest",'):
            with self.subTest(member=member):
                self.assertNotIn(self.author(member=member)[0], ("PASS_ADD", "PASS_REPL"))


if __name__ == "__main__":
    unittest.main()
