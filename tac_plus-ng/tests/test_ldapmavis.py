"""LDAP backends against a real OpenLDAP slapd: ldapmavis-mt (external-mt), mavis_tacplus-ng_ldap.pl and
mavis_tacplus_ldap.py (external).

Every test starts a slapd of its own, as a normal process on a free
loopback port, with a database that slapadd fills before the start. The
anonymous user can only bind, so the backend must bind as LDAP_USER to
search. alice is a member of netadmins, and netadmins is a member of
staff; dave is a direct member of staff; bob is in no group.
"""

import glob
import os
import re
import select
import shutil
import socket
import string
import subprocess
import tempfile
import time
import unittest

from tactest import LINUX, DaemonTestCase, prefix, tls
from tactest.daemon import free_port

SLAPD = shutil.which("slapd") or "/usr/sbin/slapd"
SCHEMA_DIRS = ("/etc/ldap/schema", "/etc/openldap/schema")
# Debian and Ubuntu build the back-ends as modules in /usr/lib/ldap, Alpine in /usr/lib/openldap
MODULE_DIRS = ("/usr/lib/ldap", "/usr/lib/openldap", "/usr/lib64/openldap", "/usr/libexec/openldap")
LDAPMAVIS = os.path.join(prefix(), "sbin", "ldapmavis-mt")
LDAP_PERL = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus-ng_ldap.pl")
PERL = shutil.which("perl") or "/usr/bin/perl"
LDAP_PYTHON = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_ldap.py")
# the interpreter of the "#!" line of the Python back-end
PYTHON = "/usr/bin/python3" if os.access("/usr/bin/python3", os.X_OK) else shutil.which("python3") or "python3"
START_TIMEOUT = 10.0

BASE = "dc=example,dc=com"
READER = "cn=reader," + BASE
STAFF = "cn=staff,ou=groups," + BASE
ALICE, BOB, DAVE = (f"uid={uid},ou=people,{BASE}" for uid in ("alice", "bob", "dave"))
# slapd -d 256 logs 'conn=1000 fd=12 TLS established ...' and 'conn=1000 op=1 BIND dn="..." method=128' (simple)
CLEAR_TEXT_WARNING = "the connection to the LDAP server has no TLS: the binds send the passwords in clear text"
TLS_OR_BIND = re.compile(r'conn=(\d+) (?:fd=\d+ (TLS) established|op=\d+ BIND dn="([^"]*)" method=128)')

ACCESS = """\
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none"""
# for a back-end without LDAP_USER
ANONYMOUS_READ = """\
access to attrs=userPassword by self write by anonymous auth by * none
access to * by * read"""
# only LDAP_USER can search, the users can only bind
READER_ONLY = f"""\
access to attrs=userPassword by anonymous auth by * none
access to * by dn.exact="{READER}" read by * none"""

SLAPD_CONF = string.Template("""\
include $core
include $cosine
include $inetorgperson
$modules
$tls
pidfile $pidfile
argsfile $argsfile

access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
$access

database mdb
suffix "$base"
directory $db
""")

LDIF = string.Template("""\
dn: $base
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: ou=people,$base
objectClass: organizationalUnit
ou: people

dn: ou=groups,$base
objectClass: organizationalUnit
ou: groups

dn: $reader
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: reader
userPassword: readerpw

dn: uid=alice,ou=people,$base
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Alice
userPassword: alicepw

dn: uid=bob,ou=people,$base
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Bob
userPassword: bobpw

dn: uid=carol,ou=people,$base
objectClass: inetOrgPerson
uid: carol
cn: Carol
sn: Carol
userPassword: carolpw

dn: uid=dave,ou=people,$base
objectClass: inetOrgPerson
uid: dave
cn: Dave
sn: Dave
userPassword: davepw

dn: cn=netadmins,ou=groups,$base
objectClass: groupOfNames
cn: netadmins
member: uid=alice,ou=people,$base

dn: $staff
objectClass: groupOfNames
cn: staff
member: cn=netadmins,ou=groups,$base
member: uid=dave,ou=people,$base
""").substitute(base=BASE, reader=READER, staff=STAFF)


def slapd_arg(value):
    """A slapd.conf argument: double quotes keep blanks, a backslash escapes a quote or a backslash."""
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def first_existing(paths):
    return next((p for p in paths if os.path.isdir(p)), None)


def modules():
    """moduleload lines for the mdb back-end, empty if slapd has it built in."""
    for d in MODULE_DIRS:
        if glob.glob(os.path.join(d, "back_mdb.*")):
            return f"modulepath {slapd_arg(d)}\nmoduleload back_mdb"
    return ""


def backend_fds(d, program):
    """The number of open files of the back-end process of daemon d that runs program (executable or script)."""
    for pid in d.descendants():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if program.encode() in f.read().split(b"\0"):
                    return len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            continue
    raise AssertionError(f"no process of {program}")


def perl_ldap():
    """The Perl back-end needs Net::LDAP and IO::Socket::SSL."""
    try:
        return subprocess.run([PERL, "-MNet::LDAP", "-MIO::Socket::SSL", "-e", "1"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False).returncode == 0
    except OSError:
        return False


def python_ldap3():
    """The Python back-end needs the ldap3 module."""
    try:
        return subprocess.run([PYTHON, "-c", "import ldap3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False).returncode == 0
    except OSError:
        return False


class Slapd:
    """slapd on 127.0.0.1, configuration and database in directory/"slapd data" (the blank tests the quoting)."""

    def __init__(self, directory, tls="", starttls=False, access=ACCESS):
        """tls: TLS lines for slapd.conf; with them slapd listens on ldaps:// only, or on ldap:// for StartTLS.

        access: the access lines, and other global lines, of slapd.conf.
        """
        self.scheme = "ldaps" if tls and not starttls else "ldap"
        directory = os.path.join(directory, "slapd data")
        os.mkdir(directory)
        self.dir = directory
        self.proc = None
        self.port = None
        self.log = os.path.join(directory, "slapd.log")
        self.conf = os.path.join(directory, "slapd.conf")
        schema = first_existing(SCHEMA_DIRS)
        if schema is None:
            raise AssertionError(f"no OpenLDAP schema directory in {SCHEMA_DIRS}")
        paths = {n: os.path.join(schema, n + ".schema") for n in ("core", "cosine", "inetorgperson")}
        paths.update(pidfile=os.path.join(directory, "slapd.pid"), argsfile=os.path.join(directory, "slapd.args"),
                     db=os.path.join(directory, "db"))
        with open(self.conf, "w") as f:
            f.write(SLAPD_CONF.substitute({k: slapd_arg(v) for k, v in paths.items()}, modules=modules(), tls=tls,
                                          access=access, base=BASE))
        os.mkdir(os.path.join(directory, "db"))
        ldif = os.path.join(directory, "data.ldif")
        with open(ldif, "w") as f:
            f.write(LDIF)
        p = subprocess.run([SLAPD, "-T", "add", "-f", self.conf, "-l", ldif], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, check=False)
        if p.returncode:
            raise AssertionError("slapadd failed:\n" + p.stdout.decode("utf-8", "replace"))

    @property
    def url(self):
        return f"{self.scheme}://127.0.0.1:{self.port}"

    def start(self):
        """Start slapd; a restart keeps the port."""
        if self.port is None:
            self.port = free_port("127.0.0.1")
        with open(self.log, "ab") as log:
            # -d keeps slapd in the foreground; 256 logs the connections and operations
            self.proc = subprocess.Popen([SLAPD, "-d", "256", "-h", self.url + "/", "-f", self.conf],
                                         stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            select.select([], [], [], 0.05)
        self.stop()
        with open(self.log, errors="replace") as f:
            raise AssertionError(f"slapd did not start on {self.url}:\n{f.read()[-3000:]}")

    def binds(self):
        """(DN, TLS) for each simple bind with a name, from the log; TLS: the connection had TLS before the bind."""
        with open(self.log, errors="replace") as f:
            text = f.read()
        binds = []
        # a restarted slapd counts its connections from the start again
        for run in text.split("slapd starting"):
            tls = set()
            for conn, established, dn in TLS_OR_BIND.findall(run):
                if established:
                    tls.add(conn)
                elif dn:
                    binds.append((dn, conn in tls))
        return binds

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


# ldapmavis-mt skips the groupOfNames search while LDAP_NESTED_GROUP_DEPTH is unset
MODULE = string.Template("""
	mavis module = $module {
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_FILTER = "(&(objectClass=inetOrgPerson)(uid=$uid))"
		setenv LDAP_NESTED_GROUP_DEPTH = "10"
$extra		exec = $exec
	}
""")

POLICY = string.Template("""
$module
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	authentication fallback = permit
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	group netadmins { }
	group staff { }
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
		rule everyone { script { permit } }
	}
""")


class LdapTests:
    """The tests for all back-ends; a subclass sets module(url, extra) to its "mavis module" block."""

    def start(self, tls="", starttls=False, access=ACCESS, check=True, settings="", **env):
        """Start slapd and the daemon; tls, starttls, access: see Slapd, settings: tac_plus-ng lines.

        env: of the back-end; None unsets a variable (LDAP_USER=None: no bind as LDAP_USER).
        """
        # a directory of its own for every slapd: a test may start more than one
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))), tls,
                      starttls, access)
        self.addCleanup(slapd.stop)
        slapd.start()
        env = {"LDAP_USER": READER, "LDAP_PASSWD": "readerpw", **env}
        extra = "".join(f'\t\tsetenv {name} = "{value}"\n' for name, value in env.items() if value is not None)
        body = settings + POLICY.substitute(module=self.module(slapd.url, extra), staff=STAFF)
        return slapd, self.start_daemon(body, check=check)

    def test_pap(self):
        _, d = self.start()
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_ascii_login(self):
        _, d = self.start()
        for password, status in (("bobpw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.ascii_login("bob", password).status_name, status)

    def test_unknown_user(self):
        _, d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap("mallory", "alicepw").status_name, "FAIL")

    def test_groups(self):
        """groupOfNames, nested: the group names become TACMEMBER, the group DNs MEMBEROF."""
        _, d = self.start()
        for user, password, motd in (("alice", "alicepw", "netadmins in staff\n"), ("dave", "davepw", "staff\n"),
                                     ("bob", "bobpw", "")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(user, password)
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_password_change(self):
        """An empty password at an ASCII login starts the password change dialog ("login backend = mavis chpass")."""
        _, d = self.start()
        with d.connect() as c:
            r = c.ascii_login("carol", "", data=["carolpw", "newpw", "newpw"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        for password, status in (("newpw", "PASS"), ("carolpw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("carol", password).status_name, status)

    def test_server_stopped(self):
        """With slapd stopped the backend reports an error, so the fallback-only user can log in."""
        slapd, d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        slapd.stop()
        with d.connect(timeout=15.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
class LdapMt(LdapTests, DaemonTestCase):
    CONFIG = None

    def module(self, url, extra):
        return MODULE.substitute(module="external-mt", url=url, base=BASE, uid="%s", extra=extra,
                                 exec=f'"{LDAPMAVIS}" "ldapmavis-mt"')


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerl(LdapTests, DaemonTestCase):
    CONFIG = None

    def module(self, url, extra):
        return MODULE.substitute(module="external", url=url, base=BASE, uid="%s", extra=extra,
                                 exec=f'"{PERL}" "perl" "{LDAP_PERL}"')


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(python_ldap3(), f"no ldap3 module for {PYTHON}")
class LdapPython(LdapTests, DaemonTestCase):
    """mavis_tacplus_ldap.py; slapd with "security simple_bind=1" refuses simple binds without TLS."""
    CONFIG = None
    exe = None

    def module(self, url, extra):
        command = f'"{self.exe}" "python3"' if self.exe else f'"{PYTHON}" "python3" "{LDAP_PYTHON}"'
        return MODULE.substitute(module="external", url=url, base=BASE, uid="{}", extra=extra,
                                 exec=command)

    def ca(self):
        """A CA with a server certificate for 127.0.0.1 and localhost."""
        ca = tls.CA("ldap ca")
        self.addCleanup(ca.remove)
        return ca

    @staticmethod
    def trust(ca):
        # ldap3 compares only the DNS names of the certificate with the host
        return {"TLS_OPTIONS": f"ca_certs_file='{ca.cert}', valid_names=['localhost']"}

    @staticmethod
    def ldaps(ca, more=""):
        return (f"TLSCACertificateFile {slapd_arg(ca.cert)}\nTLSCertificateFile {slapd_arg(ca.server[0])}\n"
                f"TLSCertificateKeyFile {slapd_arg(ca.server[1])}\n{more}")

    def login(self, d):
        with d.connect(timeout=15.0) as c:
            return c.pap("alice", "alicepw").status_name

    def assert_login(self, d, status):
        """alice gets status; the fallback-only user can log in only if it is the backend error (FAIL)."""
        self.assertEqual(self.login(d), status)
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS" if status == "FAIL" else "FAIL")

    def capture_stderr(self, name):
        """The next start() runs the back-end through a script that writes its stderr to the file name.

        MAVIS logs the stderr of the back-end to syslog only.
        """
        log = self.scratch_file(name + ".log", "")
        self.exe = self.scratch_file(name + ".sh", f'#!/bin/sh\nexec "{PYTHON}" "{LDAP_PYTHON}" 2>>"{log}"\n')
        os.chmod(self.exe, 0o755)
        return log

    def stderr(self, log, text=None):
        """The stderr of the back-end; with text, wait up to 10 s until it shows text."""
        deadline = time.monotonic() + 10
        while True:
            with open(log, errors="replace") as f:
                content = f.read()
            if text is None or text in content or time.monotonic() > deadline:
                return content
            time.sleep(0.1)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_offered(self):
        """ldap:// to a server that offers StartTLS: StartTLS before all binds, a failure is a backend error.

        LDAP_SKIP_STARTTLS=1 sends the binds in clear text.
        """
        ca = self.ca()
        refuse_clear = self.ldaps(ca, "security simple_bind=1\n")
        with self.subTest("CA not trusted"):
            log = self.capture_stderr("untrusted")
            slapd, d = self.start(tls=refuse_clear, starttls=True)
            self.assert_login(d, "FAIL")
            self.assertEqual(slapd.binds(), [])
            self.assertIn("StartTLS: ", self.stderr(log))
        with self.subTest("CA trusted"):
            log = self.capture_stderr("trusted")
            slapd, d = self.start(tls=refuse_clear, starttls=True, **self.trust(ca))
            self.assert_login(d, "PASS")
            self.assertTrue(slapd.binds())
            self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
            self.assertNotIn(CLEAR_TEXT_WARNING, self.stderr(log))
        with self.subTest("LDAP_SKIP_STARTTLS"):
            log = self.capture_stderr("skip")
            slapd, d = self.start(tls=self.ldaps(ca), starttls=True, LDAP_SKIP_STARTTLS="1")
            self.assert_login(d, "PASS")
            self.assertIn((READER, False), slapd.binds())
            self.assertIn(CLEAR_TEXT_WARNING, self.stderr(log))

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_required(self):
        """USE_STARTTLS: StartTLS before all binds; a server without StartTLS is a backend error."""
        ca = self.ca()
        with self.subTest("StartTLS"):
            slapd, d = self.start(tls=self.ldaps(ca, "security simple_bind=1\n"), starttls=True, USE_STARTTLS="1",
                                  **self.trust(ca))
            self.assert_login(d, "PASS")
            self.assertTrue(slapd.binds())
            self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
        with self.subTest("no StartTLS"):
            slapd, d = self.start(USE_STARTTLS="1")
            self.assert_login(d, "FAIL")
            self.assertEqual(slapd.binds(), [])

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_clear_text_warning(self):
        """A connection without TLS gives a warning on stderr before the bind; ldaps:// gives none."""
        log = self.capture_stderr("ldap")
        _, d = self.start()
        self.assert_login(d, "PASS")
        self.assertIn(CLEAR_TEXT_WARNING, self.stderr(log, CLEAR_TEXT_WARNING))
        ca = self.ca()
        log = self.capture_stderr("ldaps")
        slapd, d = self.start(tls=self.ldaps(ca), **self.trust(ca))
        self.assert_login(d, "PASS")
        self.assertEqual(slapd.url[:8], "ldaps://")
        self.assertNotIn(CLEAR_TEXT_WARNING, self.stderr(log))

    @unittest.skipUnless(LINUX, "the open files of the back-end are found through /proc")
    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_failed_starttls_closes_the_connection(self):
        """Each login after a failed StartTLS tries a new connection; the back-end must close the old socket."""
        ca = self.ca()
        _, d = self.start(tls=self.ldaps(ca), starttls=True)
        self.assertEqual(self.login(d), "FAIL")
        before = backend_fds(d, LDAP_PYTHON)
        for _ in range(10):
            self.assertEqual(self.login(d), "FAIL")
        self.assertEqual(backend_fds(d, LDAP_PYTHON), before)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_reconnect_starts_tls(self):
        """After slapd restarts, the back-end opens a new connection: StartTLS comes before its bind too."""
        ca = self.ca()
        log = self.capture_stderr("reconnect")
        # after a backend error, only fallback-only users can log in for this period
        slapd, d = self.start(tls=self.ldaps(ca, "security simple_bind=1\n"), starttls=True,
                              settings="authentication fallback period = 1\n", **self.trust(ca))
        self.assert_login(d, "PASS")
        slapd.stop()
        before = len(slapd.binds())
        slapd.start()
        # the old connection is closed: a backend error, then a new connection
        self.assertEqual(self.login(d), "FAIL")
        self.assertIn("session terminated by server", self.stderr(log))
        select.select([], [], [], 2.5)
        self.assertEqual(self.login(d), "PASS", self.stderr(log))
        self.assertIn((READER, True), slapd.binds()[before:])
        self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])

    def test_failed_login_without_ldap_user(self):
        """Without LDAP_USER the back-end searches anonymously; a failed login must not break the next request."""
        _, d = self.start(access=ANONYMOUS_READ, LDAP_USER=None, LDAP_PASSWD=None)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "wrong").status_name, "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("bob", "bobpw").status_name, "PASS")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")

    def test_ldap_user_bind_each_request(self):
        """Each request binds as LDAP_USER once, then as the user; a wrong password goes to the server once."""
        slapd, d = self.start()
        logins = (("alice", "wrong", "FAIL"), ("bob", "bobpw", "PASS"), ("dave", "davepw", "PASS"))
        for user, password, status in logins:
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)
        self.assertEqual([dn for dn, _ in slapd.binds()], [READER, ALICE, READER, BOB, READER, DAVE])

    def test_searches_as_ldap_user(self):
        """Only LDAP_USER can read the directory: the searches and the group walk of each request run as LDAP_USER."""
        _, d = self.start(access=READER_ONLY)
        for user, motd in (("alice", "netadmins in staff\n"), ("dave", "staff\n")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(user, user + "pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_empty_password(self):
        """An empty password is a FAIL without a bind, not a backend error.

        This slapd accepts a bind with a DN and no password ("allow bind_anon_dn").
        """
        slapd, d = self.start(access=ACCESS + "\nallow bind_anon_dn")
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "").status_name, "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        self.assertNotIn(ALICE, [dn for dn, _ in slapd.binds()])

    def test_starttls_settings_invalid(self):
        """USE_STARTTLS with LDAP_SKIP_STARTTLS=1, or a LDAP_SKIP_STARTTLS that is not a number, stops the back-end."""
        cases = (({"USE_STARTTLS": "1", "LDAP_SKIP_STARTTLS": "1"},
                  "USE_STARTTLS and LDAP_SKIP_STARTTLS=1 contradict each other"),
                 ({"LDAP_SKIP_STARTTLS": "yes"}, "invalid LDAP_SKIP_STARTTLS: 'yes'"))
        for i, (env, message) in enumerate(cases):
            with self.subTest(env=env):
                log = self.capture_stderr(f"invalid-{i}")
                # check=False: the back-end exits on purpose
                self.start(check=False, **env)
                self.assertIn(message, self.stderr(log, message))


if __name__ == "__main__":
    unittest.main()
