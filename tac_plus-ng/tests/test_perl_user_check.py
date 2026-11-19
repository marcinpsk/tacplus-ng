"""The Perl back-ends answer FAIL for a user name that fails their user name check.

ERROR tells the daemon that the back-end failed, and starts the fallback
period for all users. The check comes before any connection to a server,
so each test runs the installed script with one request on stdin.
"""

import os
import shutil
import subprocess
import unittest

from tactest import prefix

LIB = os.path.join(prefix(), "lib", "mavis")
PERL = shutil.which("perl") or "/usr/bin/perl"
# the stderr of a script that cannot start for a missing Perl module
MISSING_MODULE = ("Can't locate ", "are available on your system")

# script, environment, a user name that fails the check of the script
BACKENDS = (
    ("mavis_tacplus-ng_ldap.pl", {}, "x,y"),
    ("mavis_tacplus_ldap.pl", {"LDAP_HOSTS": "ldap://127.0.0.1:1"}, "x,y"),
    ("mavis_ldap_authonly.pl", {}, "x&y"),
    ("mavis_tacplus_passwd.pl", {}, "@"),
    ("mavis_tacplus_sms.pl", {}, "@"),
    ("mavis_tacplus_radius.pl", {}, "@"),
    ("mavis_tacplus_opie.pl", {}, "@"),
)


def answer(script, env, user):
    """The attributes and the result code of the answer of script to an AUTH request for user."""
    request = f"0 TACPLUS\n4 {user}\n8 pw\n49 AUTH\n=\n".encode()
    p = subprocess.run([PERL, os.path.join(LIB, script)], input=request, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30, env=dict(os.environ, PERL5LIB=LIB, **env), check=False)
    out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    if "\n=" not in "\n" + out and any(m in err for m in MISSING_MODULE):
        raise unittest.SkipTest(f"{script}: a Perl module is missing")
    lines = out.splitlines()
    av = dict(line.split(" ", 1) for line in lines if " " in line and not line.startswith("="))
    return av, next((line[1:] for line in lines if line.startswith("=")), None), err


@unittest.skipUnless(os.path.isfile(os.path.join(LIB, "Mavis.pm")), "the installation has no Perl back-ends")
class PerlUserCheck(unittest.TestCase):
    def test_invalid_user_name(self):
        for script, env, user in BACKENDS:
            with self.subTest(script=script, user=user):
                av, result, err = answer(script, env, user)
                self.assertEqual((av.get("6"), result), ("NAK", "0"), (av, err))


if __name__ == "__main__":
    unittest.main()
