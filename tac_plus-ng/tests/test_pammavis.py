"""pammavis-mt with a real PAM stack: a password that PAM reports as expired (PAM_AUTHTOK_EXPIRED).

A PAM service file must be in /etc/pam.d, so these tests run in a user and
mount namespace of their own: Namespace runs this module again under
"unshare --user --mount --map-root-user" with TACTEST_PAMNS set, and only
there the PAM tests load (load_tests). In the namespace, setUpModule puts a
directory with the service file on /etc/pam.d. The service accepts every
password (pam_debug), and the account check reports an expired password
(pam_debug) until a password change (pam_exec) made the flag file.

TACTEST_REQUIRE_PAM=1 turns the skip into a failure when the namespace
cannot be made (CI sets it, so that a skip cannot pass).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tactest import LINUX, DaemonTestCase, prefix

PAMNS = "TACTEST_PAMNS"
REQUIRE = "TACTEST_REQUIRE_PAM"
UNSHARE = ["unshare", "--user", "--mount", "--map-root-user"]
PAMMAVIS = os.path.join(prefix(), "sbin", "pammavis-mt")
SERVICE = "tactest"
INNER_TIMEOUT = 300
# __name__ is __main__ when the file runs directly
MODULE = os.path.splitext(os.path.basename(__file__))[0]
# in the namespace: the directory on /etc/pam.d, with the flag file of a changed password
PAM_DIR = tempfile.mkdtemp(prefix="tactest-pam-") if os.environ.get(PAMNS) else None
CHANGED = os.path.join(PAM_DIR, "changed") if PAM_DIR else None

# the account check skips the expired password once the flag file exists
SERVICE_FILE = """\
auth required pam_debug.so auth=success
account [success=1 default=ignore] pam_exec.so quiet {test} -e {changed}
account required pam_debug.so acct=authtok_expired
account required pam_permit.so
password required pam_exec.so quiet {touch} {changed}
"""


def setUpModule():
    if os.environ.get(PAMNS):
        with open(os.path.join(PAM_DIR, SERVICE), "w") as f:
            f.write(SERVICE_FILE.format(test=shutil.which("test"), touch=shutil.which("touch"), changed=CHANGED))
        subprocess.run(["mount", "--bind", PAM_DIR, "/etc/pam.d"], check=True)


def tearDownModule():
    if PAM_DIR:
        shutil.rmtree(PAM_DIR)


def namespace_problem():
    """Why no namespace with a directory of our own on /etc/pam.d can be made here, or None."""
    if not LINUX:
        return "Linux only"
    if not os.path.exists(PAMMAVIS):
        return "the build has no pammavis-mt"
    for tool in ("unshare", "mount", "test", "touch"):
        if not shutil.which(tool):
            return f"no {tool} command"
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run(UNSHARE + ["mount", "--bind", d, "/etc/pam.d"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=30, check=False)
    if p.returncode:
        return "no bind mount on /etc/pam.d in a user namespace: " + p.stdout.decode("utf-8", "replace").strip()
    return None


class Namespace(unittest.TestCase):
    patterns = ()

    def test_pam_tests_in_a_mount_namespace(self):
        problem = namespace_problem()
        if problem:
            # a build without PAM has nothing to test
            if os.environ.get(REQUIRE) and os.path.exists(PAMMAVIS):
                self.fail(f"{REQUIRE} is set, but {problem}")
            self.skipTest(problem)
        env = dict(os.environ, **{PAMNS: "1"})
        selection = [arg for pattern in self.patterns for arg in ("-k", pattern)]
        p = subprocess.run(UNSHARE + [sys.executable, "-m", "unittest", "-v", *selection, MODULE],
                           cwd=os.path.dirname(os.path.abspath(__file__)), env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=INNER_TIMEOUT, check=False)
        out = p.stdout.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, "PAM tests in the namespace failed:\n" + out)
        self.assertRegex(out, r"\nRan [1-9]", out)


class ExpiredPassword(DaemonTestCase):
    """PAM_AUTHTOK_EXPIRED: pammavis-mt sends PASSWORD_MUSTCHANGE, so the daemon starts the password change dialog."""

    CONFIG = f"""
	mavis module = external-mt {{
		exec = "{PAMMAVIS}" "pammavis-mt" "-s" "{SERVICE}"
	}}
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	ruleset {{
		rule {{ script {{ permit }} }}
	}}
"""
    # the user must be in the passwd file; in the namespace that is root
    USER = "root"

    def setUp(self):
        super().setUp()
        if os.path.exists(CHANGED):
            os.unlink(CHANGED)

    def test_ascii_login_asks_for_a_new_password(self):
        with self.daemon.connect() as c:
            r = c.ascii_login(self.USER, "old", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        self.assertTrue(os.path.exists(CHANGED), "PAM did not change the password")
        with self.daemon.connect() as c:
            r = c.ascii_login(self.USER, "new")
        self.assertEqual(r.statuses, ["GETPASS", "PASS"], r)

    def test_pap_fails(self):
        """PAP cannot change the password."""
        with self.daemon.connect() as c:
            self.assertEqual(c.pap(self.USER, "old").status_name, "FAIL")
        self.assertFalse(os.path.exists(CHANGED))


def load_tests(loader, tests, pattern):
    """The PAM tests only in the namespace; outside it, the test that runs the selected ones there."""
    classes = [ExpiredPassword]
    if os.environ.get(PAMNS):
        return unittest.TestSuite(loader.loadTestsFromTestCase(cls) for cls in classes)
    test = Namespace("test_pam_tests_in_a_mount_namespace")
    if loader.testNamePatterns and any(loader.getTestCaseNames(cls) for cls in classes):
        test.patterns = loader.testNamePatterns
    elif loader.testNamePatterns and not loader.getTestCaseNames(Namespace):
        return unittest.TestSuite()
    return unittest.TestSuite([test])


if __name__ == "__main__":
    unittest.main()
