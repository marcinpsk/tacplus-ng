"""tests/loopback-aliases against a fake ifconfig: what it adds to lo0, and when it stops."""

import ast
import glob
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
echo "${UNAME:-FreeBSD}"
"""
# "ip -6 addr show dev lo" prints $LO; "ip -6 addr add" fails for an address in $LO, as ip does
FAKE_IP = """#!/bin/sh
echo "ip $*" >> "$CALLS"
[ "$*" = "-6 addr show dev lo" ] && printf '%s\\n' "$LO"
case "$*" in "-6 addr add "*) case "$LO" in *"inet6 ${4%/*}/"*) exit 2 ;; esac ;; esac
exit 0
"""
LO0 = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000"
LO = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN qlen 1000\n    inet6 ::1/128 scope host noprefixroute"


class LoopbackAliases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tactest-loopback-aliases-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tests = os.path.join(self.tmp, "tests")
        os.makedirs(os.path.join(self.tests, "tactest"))
        shutil.copy(SCRIPT, self.tests)
        self.write("tests/test_a.py", 'NAS = "127.1.2.3"\nNAS6 = "fd00:7ac::6"\n')
        self.write("tests/tactest/b.py", "")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.write("bin/ifconfig", FAKE_IFCONFIG, 0o755)
        self.write("bin/uname", FAKE_UNAME, 0o755)
        self.write("bin/ip", FAKE_IP, 0o755)
        self.calls = os.path.join(self.tmp, "calls")

    def write(self, name, text, mode=0o644):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)

    def run_script(self, lo0=LO0, lo=LO, **env):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], CALLS=self.calls, LO0=lo0, LO=lo,
                   **env)
        p = subprocess.run(["sh", "tests/loopback-aliases"], cwd=self.tmp, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode()

    def calls_of(self, prefix):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return [line.split() for line in f if line.startswith(prefix)]

    def aliases(self):
        return [c[3] for c in self.calls_of("ifconfig lo0 inet") if c[-1] == "alias"]

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

    def test_adds_the_ipv6_address(self):
        code, out = self.run_script()
        self.assertEqual(code, 0, out)
        self.assertIn("fd00:7ac::6/128", self.aliases())

    def test_keeps_an_ipv6_address_that_lo0_has(self):
        code, out = self.run_script(LO0 + "\n\tinet6 fd00:7ac::6 prefixlen 64")
        self.assertEqual(code, 0, out)
        self.assertNotIn("fd00:7ac::6/128", self.aliases())

    def test_linux_adds_only_the_ipv6_address(self):
        code, out = self.run_script(UNAME="Linux")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.calls_of("ifconfig"), [])
        self.assertEqual(self.calls_of("ip -6 addr add"), [["ip", "-6", "addr", "add", "fd00:7ac::6/128", "dev", "lo"]])

    def test_linux_second_run(self):
        """A second run finds the address on lo and adds nothing; "ip addr add" would fail and stop the script."""
        code, out = self.run_script(lo=LO + "\n    inet6 fd00:7ac::6/128 scope global", UNAME="Linux")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.calls_of("ip -6 addr add"), [])

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


class LoopbackSkips(unittest.TestCase):
    def test_no_test_skips_the_loopback_addresses_off_linux(self):
        """The BSDs have the addresses after tests/loopback-aliases: skip on LOOPBACK_NET, not on LINUX."""
        found = []
        for path in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_*.py"))):
            with open(path) as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "skipUnless" and len(node.args) == 2
                        and getattr(node.args[0], "id", "") == "LINUX"
                        and "127.0.0.0/8" in str(getattr(node.args[1], "value", ""))):
                    found.append("%s:%d" % (os.path.basename(path), node.lineno))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
