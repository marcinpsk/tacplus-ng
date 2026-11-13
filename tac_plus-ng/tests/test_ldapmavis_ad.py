"""LDAP backends against Active Directory (a Samba AD DC): ldapmavis-mt (external-mt) and mavis_tacplus-ng_ldap.pl.

samba-dc/start runs the DC in a container and prints the TACTEST_SAMBA_*
variables (see README); without TACTEST_SAMBA_DC the tests are skipped.
Each test class adds its users and groups to an OU of its own, with the
ldap-utils commands over LDAPS as the domain administrator, and removes
them at the end. So the tests can run again against the same DC. The
back-ends get no LDAP_FILTER: they must detect AD to find the users by
sAMAccountName.
"""

import base64
import os
import secrets
import shutil
import string
import subprocess
import time
import unittest

from tactest import DaemonTestCase
from test_ldapmavis import LDAP_PERL, LDAPMAVIS, PERL, perl_ldap

URL = os.environ.get("TACTEST_SAMBA_DC")
SETTINGS = ("TACTEST_SAMBA_BASE", "TACTEST_SAMBA_ADMIN", "TACTEST_SAMBA_PASSWORD", "TACTEST_SAMBA_CA")
SKIP_REASON = "TACTEST_SAMBA_DC is unset (see samba-dc/start in README)"

SECOND = -10000000          # AD time spans: 100 ns units, negative
PASSWORD_MAX_AGE = 1        # seconds, for the users with an expired password
LOCKOUT_THRESHOLD = 2
POSIX_GID = 4711

# a fine-grained password policy (PSO) for some users of the OU
PSO = string.Template("""\
dn: $dn
objectClass: msDS-PasswordSettings
msDS-PasswordSettingsPrecedence: 10
msDS-PasswordReversibleEncryptionEnabled: FALSE
msDS-PasswordHistoryLength: 0
msDS-PasswordComplexityEnabled: FALSE
msDS-MinimumPasswordLength: 1
msDS-MinimumPasswordAge: 0
msDS-MaximumPasswordAge: $max_age
msDS-LockoutThreshold: $lockout
msDS-LockoutObservationWindow: $hour
msDS-LockoutDuration: $hour
$applies""")

# the bind errors of AD for the correct password: user, data code, the text of the back-ends
BIND_ERRORS = (
    ("mustchange", "773", "User must reset password."),
    ("disabled", "533", "Account disabled."),
    ("expired", "701", "Account expired."),
    ("nohours", "530", "Not permitted to logon at this time."),
    ("elsewhere", "531", "Not permitted to logon at this workstation."),
    ("pwexpired", "532", "Password expired."),
    ("locked", "775", "User account locked."),
)


def settings():
    """The TACTEST_SAMBA_* values; with TACTEST_SAMBA_DC set, a missing one is an error."""
    missing = [k for k in SETTINGS if not os.environ.get(k)]
    if missing:
        raise AssertionError("TACTEST_SAMBA_DC is set, but not " + ", ".join(missing))
    return {k: os.environ[k] for k in SETTINGS}


def unicode_pwd(password):
    """The unicodePwd value for LDIF: the password in double quotes, UTF-16LE, base64."""
    return base64.b64encode(('"%s"' % password).encode("utf-16-le")).decode()


def ldap_tool(tool, args, stdin, ok=(0,)):
    """Run an ldap-utils command as the domain administrator, with the certificate check of the DC."""
    s = settings()
    path = shutil.which(tool)
    if path is None:
        raise AssertionError(f"TACTEST_SAMBA_DC is set, but {tool} (ldap-utils) is missing")
    env = dict(os.environ, LDAPTLS_CACERT=s["TACTEST_SAMBA_CA"], LDAPTLS_REQCERT="demand")
    p = subprocess.run([path, "-x", "-H", URL, "-D", s["TACTEST_SAMBA_ADMIN"], "-w", s["TACTEST_SAMBA_PASSWORD"],
                        *args], input=stdin, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                       check=False, timeout=60)
    if p.returncode not in ok:
        raise AssertionError(f"{tool} failed ({p.returncode}):\n{p.stdout}")


class Domain:
    """The users and groups of one test class, in OU=tactest-<tag>; the login name of a user is <cn>-<tag>.

    alice is a member of netadmins, netadmins of staff, dave of staff;
    posix has the gidNumber of the posixGroup unix. The account states
    of the BIND_ERRORS users, and of reset (773) and aged (532), give
    the bind errors of AD.
    """

    # cn: (userAccountControl, more LDIF lines); 512: a normal account, 514: disabled
    USERS = {
        "reader": (512, ""),
        "alice": (512, ""),
        "bob": (512, ""),
        "carol": (512, ""),
        "dave": (512, ""),
        "posix": (512, f"gidNumber: {POSIX_GID}\n"),
        "mustchange": (512, "pwdLastSet: 0\n"),
        "reset": (512, "pwdLastSet: 0\n"),
        "disabled": (514, ""),
        "expired": (512, "accountExpires: 1\n"),
        "nohours": (512, "logonHours:: %s\n" % base64.b64encode(bytes(21)).decode()),
        "elsewhere": (512, "userWorkstations: nowhere\n"),
        "pwexpired": (512, ""),
        "aged": (512, ""),
        "locked": (512, ""),
    }

    def __init__(self):
        self.base = settings()["TACTEST_SAMBA_BASE"]
        self.tag = secrets.token_hex(3)
        self.ou = f"OU=tactest-{self.tag},{self.base}"
        self.psos = {what: f"CN=tactest-{self.tag}-{what},CN=Password Settings Container,CN=System,{self.base}"
                     for what in ("expired", "lockout")}
        self.created = None

    def login(self, cn):
        return f"{cn}-{self.tag}"

    def dn(self, cn):
        return f"CN={cn},{self.ou}"

    @staticmethod
    def password(cn):
        return cn + "-pw"

    def create(self):
        ldif = [f"dn: {self.ou}\nobjectClass: organizationalUnit\n"]
        for cn, (uac, more) in self.USERS.items():
            ldif.append(f"dn: {self.dn(cn)}\nobjectClass: user\nsAMAccountName: {self.login(cn)}\n"
                        f"unicodePwd:: {unicode_pwd(self.password(cn))}\nuserAccountControl: {uac}\n{more}")
        for cn, members in (("netadmins", ["alice"]), ("staff", ["netadmins", "dave"])):
            ldif.append(f"dn: {self.dn(cn)}\nobjectClass: group\nsAMAccountName: {self.login(cn)}\n"
                        + "".join(f"member: {self.dn(m)}\n" for m in members))
        ldif.append(f"dn: {self.dn('unix')}\nobjectClass: group\nobjectClass: posixGroup\n"
                    f"sAMAccountName: {self.login('unix')}\ngidNumber: {POSIX_GID}\n")
        hour = 3600 * SECOND
        for what, max_age, lockout, users in (("expired", PASSWORD_MAX_AGE * SECOND, 0, ("pwexpired", "aged")),
                                              ("lockout", 1000 * hour, LOCKOUT_THRESHOLD, ("locked",))):
            applies = "".join(f"msDS-PSOAppliesTo: {self.dn(u)}\n" for u in users)
            ldif.append(PSO.substitute(dn=self.psos[what], max_age=max_age, lockout=lockout, hour=hour,
                                       applies=applies))
        ldap_tool("ldapadd", [], "\n".join(ldif))
        self.created = time.monotonic()

    def remove(self):
        # 32: no such object, after a create() that stopped early
        ldap_tool("ldapdelete", ["-c"], "".join(dn + "\n" for dn in self.psos.values()), ok=(0, 32))
        ldap_tool("ldapdelete", ["-r", self.ou], None, ok=(0, 32))

    def wait_password_expired(self):
        time.sleep(max(0.0, self.created + PASSWORD_MAX_AGE + 1 - time.monotonic()))


MODULE = string.Template("""
	mavis module = $module {
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_USER = "$reader"
		setenv LDAP_PASSWD = "$readerpw"
$env
		exec = $exec
	}
""")

POLICY = string.Template("""
$module
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	group netadmins { }
	group staff { }
	group unix { }
	ruleset {
		rule nested {
			script { if (member == netadmins && memberof == "$staff") { motd banner = "netadmins in staff\\n" permit } }
		}
		rule netadmins {
			script { if (member == netadmins) { motd banner = "netadmins only\\n" permit } }
		}
		rule staff {
			script { if (memberof == "$staff") { motd banner = "staff\\n" permit } }
		}
		rule unix {
			script { if (member == unix) { motd banner = "unix\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")


class AdTests:
    """The tests for both back-ends; a subclass sets MODULE, EXEC and env() (its TLS settings)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.domain = Domain()
        cls.addClassCleanup(cls.domain.remove)
        cls.domain.create()

    def start(self, **env):
        d = self.domain
        lines = "\n".join(f'\t\tsetenv {k} = "{v}"' for k, v in {**self.env(), **env}.items())
        module = MODULE.substitute(module=self.MODULE, url=URL, base=d.ou, reader=d.dn("reader"),
                                   readerpw=d.password("reader"), env=lines, exec=self.EXEC)
        return self.start_daemon(POLICY.substitute(module=module, staff=d.dn("staff")))

    def login(self, cn):
        return self.domain.login(cn)

    def lock(self, d):
        """Lock the account "locked" with wrong passwords."""
        for _ in range(LOCKOUT_THRESHOLD):
            with d.connect() as c:
                self.assertEqual(c.pap(self.login("locked"), "wrong").status_name, "FAIL")

    def test_pap(self):
        """No LDAP_FILTER: the AD default (sAMAccountName) finds the user."""
        d = self.start()
        for password, status in (("alice-pw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("alice"), password).status_name, status)

    def test_ascii_login(self):
        d = self.start()
        for password, status in (("bob-pw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.ascii_login(self.login("bob"), password).status_name, status)

    def test_unknown_user(self):
        d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap(self.login("nobody"), "alice-pw").status_name, "FAIL")

    def test_groups(self):
        """memberOf of AD, nested: the group names become TACMEMBER, the group DNs MEMBEROF."""
        d = self.start()
        for user, motd in (("alice", "netadmins in staff\n"), ("dave", "staff\n"), ("bob", "")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(self.login(user), user + "-pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_posixgroup(self):
        """On AD the back-ends skip the posixGroup search, unless LDAP_SKIP_POSIXGROUP=0."""
        for env, motd in (({}, ""), ({"LDAP_SKIP_POSIXGROUP": "0"}, "unix\n")):
            d = self.start(**env)
            with self.subTest(env=env), d.connect() as c:
                r = c.ascii_login(self.login("posix"), "posix-pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_password_change(self):
        """The password change dialog sets unicodePwd (UTF-16LE: the new password is not ASCII)."""
        d = self.start()
        new = "carol-neu-ä€"
        with d.connect() as c:
            r = c.ascii_login(self.login("carol"), "", data=["wrong", new, new])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "FAIL"], r)
        with d.connect() as c:
            r = c.ascii_login(self.login("carol"), "", data=["carol-pw", new, new])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        for password, status in ((new, "PASS"), ("carol-pw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("carol"), password).status_name, status)

    def test_bind_errors(self):
        """The correct password of an account that AD does not let log in: FAIL, also without a password change."""
        d = self.start()
        self.lock(d)
        self.domain.wait_password_expired()
        for user, code, _ in BIND_ERRORS:
            with self.subTest(user=user, code=code), d.connect() as c:
                self.assertEqual(c.pap(self.login(user), user + "-pw").status_name, "FAIL")
            if code in ("773", "533", "532"):
                continue
            with self.subTest(user=user, code=code, login="ascii"), d.connect() as c:
                self.assertEqual(c.ascii_login(self.login(user), user + "-pw").statuses, ["GETPASS", "FAIL"])


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
class AdMt(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external-mt"
    EXEC = f'"{LDAPMAVIS}" "ldapmavis-mt"'

    def env(self):
        return {"LDAP_OPT_X_TLS_CACERTFILE": settings()["TACTEST_SAMBA_CA"],
                "LDAP_OPT_X_TLS_REQUIRE_CERT": "LDAP_OPT_X_TLS_DEMAND"}


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class AdPerl(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external"
    EXEC = f'"{PERL}" "perl" "{LDAP_PERL}"'

    def env(self):
        return {"TLS_OPTIONS": f"verify => 'require', cafile => '{settings()['TACTEST_SAMBA_CA']}'"}

    def test_bind_error_messages(self):
        """The text for the "data" code of the AD bind error goes to the client."""
        d = self.start()
        self.lock(d)
        self.domain.wait_password_expired()
        for user, code, text in BIND_ERRORS + (("alice", "52e", "Invalid credentials."),):
            password = "wrong" if user == "alice" else user + "-pw"
            with self.subTest(user=user, code=code), d.connect() as c:
                r = c.pap(self.login(user), password)
                self.assertEqual((r.status_name, r.server_msg), ("FAIL", text + "\n"), r)

    def test_must_change(self):
        """A password that must change (773) or that expired (532) starts the password change dialog."""
        d = self.start()
        self.domain.wait_password_expired()
        for user in ("reset", "aged"):
            new = user + "-new"
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(self.login(user), user + "-pw", data=[new, new])
                self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        # the policy of aged lets its new password expire at once
        for password, status in (("reset-new", "PASS"), ("reset-pw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("reset"), password).status_name, status)


if __name__ == "__main__":
    unittest.main()
