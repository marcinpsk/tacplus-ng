"""tests/loopback-aliases against a fake ifconfig: what it adds to lo0, and when it stops."""

import os
import shutil
import subprocess
import tempfile
import unittest

from tactest import SOURCE

SCRIPT = os.path.join(SOURCE, "tac_plus-ng", "tests", "loopback-aliases")

# the fake commands log each call; "ifconfig lo0" prints $LO0
FAKE_IFCONFIG = """#!/bin/sh
echo "ifconfig $*" >> "$CALLS"
[ "$*" = lo0 ] && printf '%s\\n' "$LO0"
exit 0
"""
FAKE_UNAME = """#!/bin/sh
echo FreeBSD
"""
LO0 = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000"


class LoopbackAliases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tactest-loopback-aliases-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tests = os.path.join(self.tmp, "tests")
        os.makedirs(os.path.join(self.tests, "tactest"))
        shutil.copy(SCRIPT, self.tests)
        self.write("tests/test_a.py", 'NAS = "127.1.2.3"\n')
        self.write("tests/tactest/b.py", "")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.write("bin/ifconfig", FAKE_IFCONFIG, 0o755)
        self.write("bin/uname", FAKE_UNAME, 0o755)
        self.calls = os.path.join(self.tmp, "calls")

    def write(self, name, text, mode=0o644):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)

    def run_script(self, lo0=LO0, **env):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], CALLS=self.calls, LO0=lo0, **env)
        p = subprocess.run(["sh", "tests/loopback-aliases"], cwd=self.tmp, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode()

    def aliases(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return [line.split()[3] for line in f
                    if line.startswith("ifconfig lo0 inet ") and line.rstrip().endswith(" alias")]

    def test_adds_the_range_and_the_named_addresses(self):
        code, out = self.run_script()
        self.assertEqual(code, 0, out)
        added = self.aliases()
        self.assertIn("127.0.0.2/32", added)
        self.assertIn("127.0.0.254/32", added)
        self.assertIn("127.1.2.3/32", added)
        self.assertNotIn("127.0.0.1/32", added)

    def test_keeps_an_address_that_lo0_has(self):
        """127.0.0.2/24 on lo0 stays as it is: no "127.0.0.2/32 alias" that replaces its netmask."""
        code, out = self.run_script(LO0 + "\n\tinet 127.0.0.2 netmask 0xffffff00")
        self.assertEqual(code, 0, out)
        added = self.aliases()
        self.assertNotIn("127.0.0.2/32", added)
        self.assertIn("127.0.0.20/32", added)

    def test_stops_when_a_test_file_cannot_be_read(self):
        os.symlink("missing.py", os.path.join(self.tests, "test_gone.py"))
        code, out = self.run_script()
        self.assertNotEqual(code, 0, out)
        self.assertEqual(self.aliases(), [])

    def test_cdpath_does_not_change_the_directory_of_the_tests(self):
        """With CDPATH set, cd prints the directory, and $(cd ... && pwd) then holds two lines."""
        code, out = self.run_script(CDPATH=".")
        self.assertEqual(code, 0, out)
        self.assertIn("127.1.2.3/32", self.aliases())


if __name__ == "__main__":
    unittest.main()
