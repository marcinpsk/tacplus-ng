"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import os
import unittest

from tactest import DaemonTestCase, Stub, config, prefix
from tactest.daemon import parse_only

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
"""

    @classmethod
    def setUpClass(cls):
        # the daemon gets the environment of the tests
        os.environ["TACTEST_ENV_GROUP"] = "admin"
        cls.addClassCleanup(os.environ.pop, "TACTEST_ENV_GROUP")
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
        """No ${VAR} in a value."""
        self.assertNotEqual(self.author(member='"${TACTEST_ENV_GROUP}"'), ("PASS_ADD", ["priv-lvl=15"]))

    def test_value_has_only_entries_of_its_attribute(self):
        """Text after the list is a parse error: no authorization."""
        for member in ('"guest" member = admin', '"guest" }', '"guest",'):
            with self.subTest(member=member):
                self.assertNotIn(self.author(member=member)[0], ("PASS_ADD", "PASS_REPL"))


if __name__ == "__main__":
    unittest.main()
