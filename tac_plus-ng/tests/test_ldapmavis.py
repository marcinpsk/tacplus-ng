"""LDAP backends against a real OpenLDAP slapd: ldapmavis-mt, mavis_tacplus-ng_ldap.pl, mavis_tacplus_ldap.pl and
mavis_tacplus_ldap.py.

Every test starts a slapd of its own, as a normal process on a free
loopback port, with a database that slapadd fills before the start. The
anonymous user can only bind, so the backend must bind as LDAP_USER to
search. alice is a member of netadmins, and netadmins is a member of
staff; dave is a direct member of staff; bob is in no group. erin and
frank have the tacacs schema of mavis/perl; the password of frank expired.
The password of grace does not expire (shadowExpire -1), that of heidi expired.
"""

import base64
import ctypes
import ctypes.util
import glob
import hashlib
import os
import re
import select
import shutil
import signal
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock

from tactest import LINUX, DaemonTestCase, Stub, prefix, tls
from tactest.daemon import free_port, sanitizer_env

SLAPD = shutil.which("slapd") or "/usr/sbin/slapd"
SCHEMA_DIRS = ("/etc/ldap/schema", "/etc/openldap/schema")
# Debian and Ubuntu build the back-ends as modules in /usr/lib/ldap, Alpine in /usr/lib/openldap
MODULE_DIRS = ("/usr/lib/ldap", "/usr/lib/openldap", "/usr/lib64/openldap", "/usr/libexec/openldap")
LDAPMAVIS = os.path.join(prefix(), "sbin", "ldapmavis-mt")
LDAP_PERL = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus-ng_ldap.pl")
LDAP_PERL_OLD = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_ldap.pl")
LDAP_PERL_AUTHONLY = os.path.join(prefix(), "lib", "mavis", "mavis_ldap_authonly.pl")
TACACS_SCHEMA = os.path.join(prefix(), "lib", "mavis", "extra", "tacacs.schema")
PERL = shutil.which("perl") or "/usr/bin/perl"
LDAP_PYTHON = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_ldap.py")
# the interpreter of the "#!" line of the Python back-end
PYTHON = "/usr/bin/python3" if os.access("/usr/bin/python3", os.X_OK) else shutil.which("python3") or "python3"
START_TIMEOUT = 10.0
LDAP_OPT_X_TLS_PACKAGE = 0x6011  # from ldap.h
CLOSE_TIMEOUT = 5.0

BASE = "dc=example,dc=com"
READER = "cn=reader," + BASE
STAFF = "cn=staff,ou=groups," + BASE
WIDE = 2000                 # groups of one user, above the 1024 of the old fixed array
# memberOf as a plain attribute, the way Active Directory has it; no overlay needed
MEMBEROF_SCHEMA = "attributetype ( 1.2.840.113556.1.2.102 NAME 'memberOf' SUP distinguishedName )\n"
ALICE, BOB, DAVE = (f"uid={uid},ou=people,{BASE}" for uid in ("alice", "bob", "dave"))
# slapd -d 256 logs 'conn=1000 fd=12 TLS established ...' and 'conn=1000 op=1 BIND dn="..." method=128' (simple)
CLEAR_TEXT_WARNING = "the connection to the LDAP server has no TLS: the binds send the passwords in clear text"
# runs the back-end argv[1]; on SIGUSR1 it writes the number of its ldap3.Connection objects to argv[2]
COUNT_CONNECTIONS = """\
import gc, os, runpy, signal, sys
script, out = sys.argv[1:3]

def count(*_):
    import ldap3
    gc.collect()
    with open(out + ".tmp", "w") as f:
        f.write(str(sum(isinstance(o, ldap3.Connection) for o in gc.get_objects())))
    os.replace(out + ".tmp", out)

signal.signal(signal.SIGUSR1, count)
# the daemon can start the back-end with SIGUSR1 blocked
signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR1})
sys.argv = [script]
sys.path.insert(0, os.path.dirname(script))
runpy.run_path(script, run_name="__main__")
"""
TLS_OR_BIND = re.compile(r'conn=(\d+) (?:fd=\d+ (TLS) established|op=\d+ BIND dn="([^"]*)" method=128)')

ACCESS = """\
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none"""
# for a back-end without LDAP_USER: only an anonymous client can search, the users can only bind
ANONYMOUS_ONLY = """\
access to attrs=userPassword by anonymous auth by * none
access to * by anonymous read by * none"""
# only LDAP_USER can search, the users can only bind
READER_ONLY = f"""\
access to attrs=userPassword by anonymous auth by * none
access to * by dn.exact="{READER}" read by * none"""

SLAPD_CONF = string.Template("""\
include $core
include $cosine
include $inetorgperson
include $nis
include $tacacs
include $memberof
$modules
sizelimit unlimited
$tls
pidfile $pidfile
argsfile $argsfile

access to dn.base="" $root_dse
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

dn: uid=erin,ou=people,$base
objectClass: inetOrgPerson
objectClass: tacacsAccount
uid: erin
cn: Erin
sn: Erin
userPassword: erinpw

dn: uid=frank,ou=people,$base
objectClass: inetOrgPerson
objectClass: shadowAccount
objectClass: tacacsAccount
uid: frank
cn: Frank
sn: Frank
userPassword: frankpw
shadowExpire: 1

dn: uid=grace,ou=people,$base
objectClass: inetOrgPerson
objectClass: shadowAccount
uid: grace
cn: Grace
sn: Grace
userPassword: gracepw
shadowExpire: -1

dn: uid=heidi,ou=people,$base
objectClass: inetOrgPerson
objectClass: shadowAccount
uid: heidi
cn: Heidi
sn: Heidi
userPassword: heidipw
shadowExpire: 1
""").substitute(base=BASE, reader=READER, staff=STAFF)


def slapd_arg(value):
    """A slapd.conf argument: double quotes keep blanks, a backslash escapes a quote or a backslash."""
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def person(uid, extra=""):
    """An LDIF entry for a user of one test, password <uid>pw; extra: more lines."""
    return (f"\ndn: uid={uid},ou=people,{BASE}\nobjectClass: inetOrgPerson\n{extra}"
            f"uid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {uid}pw\n")


def perl_string(value):
    """value as a Perl string literal: TLS_OPTIONS of the Perl back-end is Perl source."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def perl_exec(case, script, stderr_log=None):
    """The exec line of a Perl back-end; stderr_log: a file for its stderr, which MAVIS logs to syslog only."""
    if not stderr_log:
        return f'"{PERL}" "perl" "{script}"'
    name = os.path.basename(stderr_log) + ".sh"
    wrapper = case.scratch_file(name, f'#!/bin/sh\nexec "{PERL}" "{script}" 2>>"{stderr_log}"\n')
    os.chmod(wrapper, 0o755)
    return f'"{wrapper}" "{name}"'


def wait_for_idle_close(slapd):
    """Wait until slapd closed a connection for its idletimeout."""
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        with open(slapd.log, errors="replace") as f:
            if "closed (idletimeout)" in f.read():
                return
        select.select([], [], [], 0.1)
    raise AssertionError("slapd closed no connection for its idletimeout")


def first_existing(paths):
    return next((p for p in paths if os.path.isdir(p)), None)


def modules():
    """moduleload lines for the mdb back-end, empty if slapd has it built in."""
    for d in MODULE_DIRS:
        if glob.glob(os.path.join(d, "back_mdb.*")):
            return f"modulepath {slapd_arg(d)}\nmoduleload back_mdb"
    return ""


def backend_pid(d, program):
    """The process ID of the back-end process of daemon d that runs program (executable or script)."""
    for pid in d.descendants():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if program.encode() in f.read().split(b"\0"):
                    return pid
        except OSError:
            continue
    raise AssertionError(f"no process of {program}")


def backend_fds(d, program):
    """The number of open files of the back-end process of daemon d that runs program (executable or script)."""
    return len(os.listdir(f"/proc/{backend_pid(d, program)}/fd"))


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


def ldap3_matches_ip():
    """True if the host name check of ldap3 accepts an IP address SAN.

    ldap3 2.9.1 on Python 3.12 does so only with backports.ssl_match_hostname 3.5.0.1 or later.
    """
    probe = ("from ldap3.core.tls import match_hostname\n"
             "match_hostname({'subjectAltName': (('IP Address', '127.0.0.1'),)}, '127.0.0.1')")
    return subprocess.run([PYTHON, "-c", probe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          check=False).returncode == 0


def libldap():
    """The libldap of ldapmavis-mt; ctypes.util.find_library needs the development files on some systems."""
    try:
        out = subprocess.run(["ldd", LDAPMAVIS], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout
    except OSError:  # no ldd, e.g. on macOS
        out = b""
    m = re.search(rb"^\s*libldap\S*\s+=>\s+(/\S+)", out, re.M)
    return m.group(1).decode() if m else ctypes.util.find_library("ldap")


def accepts_tls12(port):
    """True if the TLS server on 127.0.0.1:port completes a TLS 1.2 handshake."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock, ctx.wrap_socket(sock):
            return True
    except (ssl.SSLError, ConnectionResetError):  # an alert, or a reset without one
        return False


def libldap_tls_package():
    """The TLS library that libldap uses, for example "OpenSSL" or "GnuTLS"."""
    name = libldap()
    if name is None:
        raise AssertionError("cannot find libldap")
    lib = ctypes.CDLL(name)
    lib.ldap_get_option.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p)
    value = ctypes.c_char_p()
    if lib.ldap_get_option(None, LDAP_OPT_X_TLS_PACKAGE, ctypes.byref(value)) != 0 or value.value is None:
        raise AssertionError("libldap does not tell its TLS package")
    package = value.value.decode()
    lib.ldap_memfree(value)
    return package


class Slapd:
    """slapd on 127.0.0.1, configuration and database in directory/"slapd data" (the blank tests the quoting)."""

    def __init__(self, directory, entries="", tls="", starttls=False, root_dse="by * read", access=ACCESS):
        """entries: more LDIF entries; tls: TLS lines for slapd.conf, with them slapd listens on ldaps:// only, or on
        ldap:// for StartTLS; root_dse: the "by" clauses of the root DSE.

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
        paths = {n: os.path.join(schema, n + ".schema") for n in ("core", "cosine", "inetorgperson", "nis")}
        paths.update(tacacs=TACACS_SCHEMA)
        paths.update(pidfile=os.path.join(directory, "slapd.pid"), argsfile=os.path.join(directory, "slapd.args"),
                     db=os.path.join(directory, "db"), memberof=os.path.join(directory, "memberof.schema"))
        with open(self.conf, "w") as f:
            f.write(SLAPD_CONF.substitute({k: slapd_arg(v) for k, v in paths.items()}, modules=modules(), tls=tls,
                                          root_dse=root_dse, access=access, base=BASE))
        with open(paths["memberof"], "w") as f:
            f.write(MEMBEROF_SCHEMA)
        os.mkdir(os.path.join(directory, "db"))
        ldif = os.path.join(directory, "data.ldif")
        with open(ldif, "w") as f:
            f.write(LDIF + entries)
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

    def open_connections(self):
        """The IDs of the client connections that slapd accepted and did not close, from its log."""
        with open(self.log, errors="replace") as f:
            text = f.read()
        return set(re.findall(r"conn=(\d+) fd=\d+ ACCEPT", text)) - set(re.findall(r"conn=(\d+) fd=\d+ closed", text))
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


def ber(tag, *parts):
    """A BER element with a definite length."""
    body = b"".join(parts)
    size = (len(body).bit_length() + 7) // 8
    length = bytes([len(body)]) if len(body) < 0x80 else bytes([0x80 | size]) + len(body).to_bytes(size, "big")
    return bytes([tag]) + length + body


def ber_split(data):
    """(tag, value, rest) of the first BER element of data, None while data holds only a part of it."""
    if len(data) < 2:
        return None
    tag, size, start = data[0], data[1], 2
    if size & 0x80:
        start += size & 0x7F
        if len(data) < start:
            return None
        size = int.from_bytes(data[2:start], "big")
    return (tag, data[start:start + size], data[start + size:]) if len(data) >= start + size else None


class StartTlsPeer:
    """An LDAP peer on ldap:// that accepts StartTLS, fails the handshake, and keeps the connection open.

    after_failure lists the operation tags that a client sent after the failed handshake (an unbind excepted),
    ops the operation tags (the request name for an extended request), hellos counts the ClientHello records.
    offer: the root DSE lists StartTLS.
    """

    SUCCESS = ber(0x0A, b"\0") + ber(0x04) + ber(0x04)
    ROOT_DSE = ber(0x64, ber(0x04), ber(0x30, ber(0x30, ber(0x04, b"supportedExtension"),
                                                  ber(0x31, ber(0x04, b"1.3.6.1.4.1.1466.20037")))))
    TLS_ALERT = bytes.fromhex("15030300020228")  # fatal handshake_failure

    def __init__(self, offer=True):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.url = "ldap://127.0.0.1:%d" % self.sock.getsockname()[1]
        self.root_dse = self.ROOT_DSE if offer else ber(0x64, ber(0x04), ber(0x30))
        self.after_failure = []
        self.ops = []
        self.hellos = 0
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        data, failed = b"", False
        with conn:
            while True:
                size = 5 + int.from_bytes(data[3:5], "big") if len(data) >= 5 else None
                if data[:1] in (b"\x15", b"\x16") and size and len(data) >= size:
                    # a TLS record: the ClientHello after the StartTLS response, or an alert of the client
                    if data[:1] == b"\x16":
                        self.hellos += 1
                        conn.sendall(self.TLS_ALERT)
                        failed = True
                    data = data[size:]
                    continue
                if data[:1] not in (b"", b"\x15", b"\x16", b"\x30"):
                    data = b""
                element = ber_split(data) if data[:1] == b"\x30" else None
                if element is None:
                    try:
                        chunk = conn.recv(65536)
                    except OSError:
                        return
                    if not chunk:
                        return
                    data += chunk
                    continue
                _, message, data = element
                _, msgid, op = ber_split(message)
                msgid = ber(0x02, msgid)
                self.ops.append(ber_split(ber_split(op)[1])[1].decode() if op[0] == 0x77 else op[0])
                if failed and op[0] != 0x42:
                    self.after_failure.append(op[0])
                if op[0] == 0x42:  # unbind
                    return
                if op[0] == 0x60:  # bind
                    conn.sendall(ber(0x30, msgid, ber(0x61, self.SUCCESS)))
                elif op[0] == 0x63:  # search
                    conn.sendall(ber(0x30, msgid, self.root_dse) + ber(0x30, msgid, ber(0x65, self.SUCCESS)))
                elif op[0] == 0x77:  # extended: StartTLS
                    conn.sendall(ber(0x30, msgid, ber(0x78, self.SUCCESS, ber(0x8A, b"1.3.6.1.4.1.1466.20037"))))

    def stop(self):
        self.sock.close()


class AdPeer:
    """An LDAP peer on ldap:// with the root DSE of Active Directory and a user alice without a uid attribute.

    While down is set, the peer closes each new connection at once. The user search finds alice only with a
    sAMAccountName filter; the bind takes the passwords readerpw and alicepw.
    """

    ROOT_DSE = ber(0x64, ber(0x04), ber(0x30, ber(0x30, ber(0x04, b"supportedCapabilities"),
                                                  ber(0x31, ber(0x04, b"1.2.840.113556.1.4.800")))))
    NO_ROOT_DSE_ATTRIBUTES = ber(0x64, ber(0x04), ber(0x30))
    ALICE = ber(0x64, ber(0x04, b"cn=alice,cn=users," + BASE.encode()),
                ber(0x30, ber(0x30, ber(0x04, b"sAMAccountName"), ber(0x31, ber(0x04, b"alice")))))

    def __init__(self):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.url = "ldap://127.0.0.1:%d" % self.sock.getsockname()[1]
        self.down = True
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            if self.down:
                conn.close()
            else:
                threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        data = b""
        with conn:
            while True:
                element = ber_split(data)
                if element is None:
                    try:
                        chunk = conn.recv(65536)
                    except OSError:
                        return
                    if not chunk:
                        return
                    data += chunk
                    continue
                _, message, data = element
                _, msgid, op = ber_split(message)
                msgid = ber(0x02, msgid)
                tag, value, _ = ber_split(op)
                fields = []
                while value and ber_split(value):
                    _, field, value = ber_split(value)
                    fields.append(field)
                if tag == 0x42:  # unbind
                    return
                if tag == 0x60:  # bind: version, name, simple password
                    code = b"\0" if fields[2] in (b"readerpw", b"alicepw") else b"\x31"
                    conn.sendall(ber(0x30, msgid, ber(0x61, ber(0x0A, code), ber(0x04), ber(0x04))))
                elif tag == 0x63:  # search: base, scope, deref, size, time, types only, filter, attributes
                    attributes, rest = [], fields[7]
                    while rest and ber_split(rest):
                        _, attribute, rest = ber_split(rest)
                        attributes.append(attribute.lower())
                    # as AD: supportedCapabilities only for all attributes, "+" or the name itself
                    root_dse = (self.ROOT_DSE if not attributes or {b"+", b"supportedcapabilities"} & set(attributes)
                                else self.NO_ROOT_DSE_ATTRIBUTES)
                    entry = root_dse if not fields[0] else self.ALICE if b"sAMAccountName" in fields[6] else b""
                    conn.sendall((ber(0x30, msgid, entry) if entry else b"") +
                                 ber(0x30, msgid, ber(0x65, StartTlsPeer.SUCCESS)))

    def stop(self):
        self.sock.close()


MODULE = string.Template("""
	mavis module = $module {
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_FILTER = "(&(objectClass=inetOrgPerson)(uid=$uid))"
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
		rule wide {
			script { if (memberof == "cn=wide-$last,ou=groups,$base") { motd banner = "wide\\n" permit } }
		}
		rule sneaky {
			script { if (memberof == "cn=sneaky,ou=groups,$base") { motd banner = "sneaky\\n" permit } }
		}
		rule special {
			script {
				if (memberof == "cn=labs,ou=groups,$base" && memberof == "cn=xparent,ou=groups,$base") {
					motd banner = "labs and xparent\\n"
					permit
				}
			}
		}
		rule top {
			script { if (memberof == "cn=l3,ou=groups,$base") { motd banner = "l3\\n" permit } }
		}
		rule cycle {
			script {
				if (memberof == "cn=cyc-a,ou=groups,$base" && memberof == "cn=cyc-b,ou=groups,$base") {
					motd banner = "cycle\\n"
					permit
				}
			}
		}
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


def setenv(env):
    """The setenv lines of a "mavis module" block; a value None sets nothing."""
    return "".join(f"\t\tsetenv {name} = {slapd_arg(value)}\n" for name, value in env.items() if value is not None)


class LdapTests:
    """The tests for all back-ends; a subclass sets module(url, extra) to its "mavis module" block.

    TRUST and NO_CHECK are the environment variables of the back-end that
    trust a CA file and that turn the check of the server certificate off.
    STARTTLS is the environment that makes StartTLS mandatory on ldap://.
    """

    # the LDAP_SCOPE values of the back-end for subtree, one level and base
    SCOPES = ("sub", "one", "base")

    def ca(self):
        """A CA with a server certificate for 127.0.0.1 and a client certificate."""
        ca = tls.CA("ldap ca")  # the blank tests the quoting in slapd.conf
        self.addCleanup(ca.remove)
        ca.client = ca.issue("client", "/O=tactest/CN=ldapmavis-mt")
        return ca

    @staticmethod
    def ldaps(ca, more=""):
        return (f"TLSCACertificateFile {slapd_arg(ca.cert)}\nTLSCertificateFile {slapd_arg(ca.server[0])}\n"
                f"TLSCertificateKeyFile {slapd_arg(ca.server[1])}\n{more}")

    def login(self, d):
        with d.connect(timeout=15.0) as c:
            return c.pap("alice", "alicepw").status_name

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_tls_server_certificate_is_checked(self):
        """By default the back-end checks the certificate of the server: a CA it does not trust is a backend error."""
        ca = self.ca()
        for env, status in (({}, "FAIL"), (self.TRUST(ca.cert), "PASS"), (dict(self.NO_CHECK), "PASS")):
            with self.subTest(env=sorted(env)):
                _, d = self.start(tls=self.ldaps(ca), **env)
                self.assertEqual(self.login(d), status)
                with d.connect() as c:
                    self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS" if status == "FAIL" else "FAIL")

    def test_failed_starttls_stops_the_connection(self):
        """After a failed StartTLS the back-end does not use the connection again, also if the peer keeps it open."""
        peer = StartTlsPeer()
        self.addCleanup(peer.stop)
        extra = setenv({"LDAP_USER": READER, "LDAP_PASSWD": "readerpw", **self.STARTTLS})
        d = self.start_daemon(POLICY.substitute(module=self.module(peer.url, extra), staff=STAFF, base=BASE,
                                                last=WIDE - 1))
        for _ in range(2):
            self.assertEqual(self.login(d), "FAIL")
            with d.connect() as c:
                self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")
        # a new connection and handshake in each round: the logins failed in the handshake, not before it
        self.assertGreaterEqual(peer.hellos, 2)
        self.assertEqual(peer.after_failure, [])

    def assert_login(self, d, status):
        """alice gets status; the fallback-only user can log in only if it is the backend error (FAIL)."""
        self.assertEqual(self.login(d), status)
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS" if status == "FAIL" else "FAIL")

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_required(self):
        """STARTTLS: StartTLS before all binds; a server without StartTLS is a backend error."""
        ca = self.ca()
        with self.subTest("StartTLS"):
            # slapd refuses simple binds without TLS
            slapd, d = self.start(tls=self.ldaps(ca, "security simple_bind=1\n"), starttls=True, **self.STARTTLS,
                                  **self.TRUST(ca.cert))
            self.assert_login(d, "PASS")
            self.assertTrue(slapd.binds())
            self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
        with self.subTest("no StartTLS"):
            slapd, d = self.start(**self.STARTTLS)
            self.assert_login(d, "FAIL")
            self.assertEqual(slapd.binds(), [])

    def slapd(self, ldif="", tls="", starttls=False, root_dse="by * read", access=ACCESS):
        """A running slapd; ldif: more entries, tls, starttls, root_dse, access: see Slapd."""
        # a directory of its own for every slapd: a test may start more than one
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))), ldif,
                      tls, starttls, root_dse, access)
        self.addCleanup(slapd.stop)
        slapd.start()
        return slapd

    def start(self, ldif="", policy="", tls="", starttls=False, root_dse="by * read", access=ACCESS, check=True,
              settings="", **env):
        """Start slapd (ldif, tls, starttls, root_dse, access: see slapd()) and the daemon; settings, policy:
        tac_plus-ng lines before and after the policy.

        env: of the back-end; None unsets a variable (LDAP_USER=None: no bind as LDAP_USER).
        """
        slapd = self.slapd(ldif, tls, starttls, root_dse, access)
        env = {"LDAP_USER": READER, "LDAP_PASSWD": "readerpw", **env}
        extra = setenv(env)
        body = settings + POLICY.substitute(module=self.module(slapd.url, extra), staff=STAFF, base=BASE,
                                            last=WIDE - 1) + policy
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

    def assert_connections_closed(self, slapd, d, logins=10):
        """logins of unknown users through d leave no connection to slapd open."""
        # the first request starts the back-end, which may keep a connection of its own
        with d.connect(timeout=15.0) as c:
            c.pap("nobody", "x")
        before = slapd.open_connections()
        for i in range(logins):
            with d.connect(timeout=15.0) as c:
                self.assertEqual(c.pap(f"nobody{i}", "x").status_name, "FAIL")
        deadline = time.monotonic() + CLOSE_TIMEOUT
        # compare IDs, not counts: a baseline connection that closes late must not hide a new one
        while slapd.open_connections() - before and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(slapd.open_connections() - before, set())

    def test_unknown_user_closes_the_connection(self):
        slapd, d = self.start()
        self.assert_connections_closed(slapd, d)

    def test_invalid_user_name(self):
        """A user name with a filter character: FAIL, not a back-end error, so no fallback for the next logins."""
        _, d = self.start()
        for user in ("x,y", "x&y"):
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, "alicepw").status_name, "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")

    def test_groups(self):
        """groupOfNames, nested without a limit (no LDAP_NESTED_GROUP_DEPTH): names become TACMEMBER, DNs MEMBEROF."""
        _, d = self.start()
        for user, password, motd in (("alice", "alicepw", "netadmins in staff\n"), ("dave", "davepw", "staff\n"),
                                     ("bob", "bobpw", "")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(user, password)
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_deep_groups(self):
        """groupOfNames without LDAP_NESTED_GROUP_DEPTH: a chain of 12 levels, the user gets the top group l3."""
        chain = [f"deep-{i}" for i in range(1, 12)] + ["l3"]
        ldif = person("deep")
        for name, member in zip(chain, [f"uid=deep,ou=people,{BASE}"] + [f"cn={g},ou=groups,{BASE}" for g in chain]):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\ncn: {name}\nmember: {member}\n"
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("deep", "deeppw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "l3\n"), r)

    def test_scope(self):
        """LDAP_SCOPE takes the documented values; the users are two levels below LDAP_BASE."""
        for scope, status in zip(self.SCOPES, ("PASS", "FAIL", "FAIL")):
            with self.subTest(scope=scope):
                _, d = self.start(LDAP_SCOPE=scope)
                with d.connect() as c:
                    self.assertEqual(c.pap("alice", "alicepw").status_name, status)

    def test_group_scope(self):
        """LDAP_SCOPE_GROUP = one below LDAP_BASE_GROUP = ou=groups finds both groups of alice."""
        _, d = self.start(LDAP_SCOPE_GROUP=self.SCOPES[1], LDAP_BASE_GROUP="ou=groups," + BASE)
        with d.connect() as c:
            r = c.ascii_login("alice", "alicepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "netadmins in staff\n"), r)

    def test_group_cycle(self):
        """cyc-a and cyc-b are members of each other: the walk ends, and both groups count."""
        ldif = person("ivan") + string.Template("""
dn: cn=cyc-a,ou=groups,$base
objectClass: groupOfNames
cn: cyc-a
member: uid=ivan,ou=people,$base
member: cn=cyc-b,ou=groups,$base

dn: cn=cyc-b,ou=groups,$base
objectClass: groupOfNames
cn: cyc-b
member: cn=cyc-a,ou=groups,$base
""").substitute(base=BASE)
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("ivan", "ivanpw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "cycle\n"), r)

    def test_filter_characters_in_a_group_dn(self):
        """A group DN with "(" or "*" finds its own parent group, and "*" matches no other group (RFC 4515)."""
        ldif = person("hank") + string.Template("""
dn: cn=ops(lab),ou=groups,$base
objectClass: groupOfNames
cn: ops(lab)
member: uid=hank,ou=people,$base

dn: cn=labs,ou=groups,$base
objectClass: groupOfNames
cn: labs
member: cn=ops(lab),ou=groups,$base

dn: cn=x*,ou=groups,$base
objectClass: groupOfNames
cn: x*
member: uid=hank,ou=people,$base

dn: cn=xparent,ou=groups,$base
objectClass: groupOfNames
cn: xparent
member: cn=x*,ou=groups,$base

dn: cn=sneaky,ou=groups,$base
objectClass: groupOfNames
cn: sneaky
member: cn=xylophone,ou=groups,$base
""").substitute(base=BASE)
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("hank", "hankpw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "labs and xparent\n"), r)

    def test_filter_characters_in_the_user_name(self):
        """A "*" in the user name matches no other user (RFC 4515), also when "mavis user filter" lets it through."""
        _, d = self.start(policy="\tacl any-user { permit }\n\tmavis user filter = any-user\n")
        for user in ("alic*", "*"):
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, "alicepw").status_name, "FAIL")

    def test_empty_user_name(self):
        """tac_plus-ng passes no empty user name on (PAP: ERROR, ASCII: it asks again); the next login works."""
        _, d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap("", "alicepw").status_name, "ERROR")
        with d.connect() as c:
            s = c.session()
            self.assertEqual(s.start(user="").status_name, "GETUSER")
            self.assertEqual(s.cont("").status_name, "GETUSER")
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")

    def test_nested_memberof(self):
        """memberOf over three levels: nell is in l1, l1 in l2, l2 in l3."""
        ldif = person("nell", f"objectClass: extensibleObject\nmemberOf: cn=l1,ou=groups,{BASE}\n")
        for name, parent in (("l1", "l2"), ("l2", "l3"), ("l3", None)):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: {name}\nmember: cn=nobody,{BASE}\n"
            if parent:
                ldif += f"memberOf: cn={parent},ou=groups,{BASE}\n"
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("nell", "nellpw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "l3\n"), r)

    def test_memberof_searches_once(self):
        """Depth 10, mos-1 in mos-2 ... in mos-9, the user is in all nine: the walk searches each group once."""
        chain = [f"mos-{i}" for i in range(1, 10)]
        ldif = person("mos", "objectClass: extensibleObject\n" + "".join(f"memberOf: cn={g},ou=groups,{BASE}\n"
                                                                         for g in chain))
        for name, parent in zip(chain, chain[1:] + [None]):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: {name}\nmember: cn=nobody,{BASE}\n"
            ldif += f"memberOf: cn={parent},ou=groups,{BASE}\n" if parent else ""
        slapd, d = self.start(ldif=ldif, LDAP_NESTED_GROUP_DEPTH="10")
        with d.connect() as c:
            self.assertEqual(c.pap("mos", "mospw").status_name, "PASS")
        with open(slapd.log, errors="replace") as f:
            log = f.read()
        for name in chain:
            searches = re.findall(rf'SRCH base="cn={name},ou=groups,{BASE}" scope=0 ', log, re.IGNORECASE)
            self.assertEqual(len(searches), 1, name)

    def test_group_depth(self):
        """LDAP_NESTED_GROUP_DEPTH = 1: only the groups that have the user as a member, not staff."""
        _, d = self.start(LDAP_NESTED_GROUP_DEPTH="1")
        with d.connect() as c:
            r = c.ascii_login("alice", "alicepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "netadmins only\n"), r)

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

    def test_no_root_dse(self):
        """A server that does not give the root DSE to LDAP_USER: the generic server type, not a backend error."""
        _, d = self.start(root_dse=f'by dn.exact="{READER}" none by * read')
        with d.connect() as c:
            r = c.ascii_login("alice", "alicepw")
            self.assertEqual((r.status_name, r.server_msg), ("PASS", "netadmins in staff\n"), r)
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
class LdapMt(LdapTests, DaemonTestCase):
    CONFIG = None
    NO_CHECK = (("LDAP_OPT_X_TLS_REQUIRE_CERT", "LDAP_OPT_X_TLS_NEVER"),)
    STARTTLS = {"USE_STARTTLS": "1"}

    @staticmethod
    def TRUST(cafile):
        return {"LDAP_OPT_X_TLS_CACERTFILE": cafile}

    exe = LDAPMAVIS

    def module(self, url, extra):
        return MODULE.substitute(module="external-mt", url=url, base=BASE, uid="%s", extra=extra,
                                 exec=f'"{self.exe}" "ldapmavis-mt"')

    def capture_stderr(self, name):
        """The next start() runs ldapmavis-mt through a script that writes its stderr to the file name.

        MAVIS logs the stderr of the back-end to syslog only.
        """
        log = self.scratch_file(name + ".log", "")
        self.exe = self.scratch_file(name + ".sh", f'#!/bin/sh\nexec "{LDAPMAVIS}" 2>>"{log}"\n')
        os.chmod(self.exe, 0o755)
        return log

    def assert_clear_text_warning(self, log, expected):
        with open(log, errors="replace") as f:
            text = f.read()
        (self.assertIn if expected else self.assertNotIn)(CLEAR_TEXT_WARNING, text)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_offered(self):
        """ldap:// to a server that offers StartTLS: StartTLS before all binds, a failure is a backend error.

        LDAP_SKIP_STARTTLS=1 sends the binds in clear text.
        """
        ca = self.ca()
        refuse_clear = self.ldaps(ca, "security simple_bind=1\n")
        with self.subTest("CA not trusted"):
            slapd, d = self.start(tls=refuse_clear, starttls=True)
            self.assert_login(d, "FAIL")
            self.assertEqual(slapd.binds(), [])
        with self.subTest("CA trusted"):
            log = self.capture_stderr("trusted")
            slapd, d = self.start(tls=refuse_clear, starttls=True, LDAP_OPT_X_TLS_CACERTFILE=ca.cert)
            self.assert_login(d, "PASS")
            self.assertTrue(slapd.binds())
            self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
            self.assert_clear_text_warning(log, False)
        with self.subTest("LDAP_SKIP_STARTTLS"):
            log = self.capture_stderr("skip")
            slapd, d = self.start(tls=self.ldaps(ca), starttls=True, LDAP_SKIP_STARTTLS="1")
            self.assert_login(d, "PASS")
            self.assertIn((READER, False), slapd.binds())
            self.assert_clear_text_warning(log, True)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_ldaps_root_dse_after_bind(self):
        """ldaps:// to a server that refuses the root DSE before a bind: TLS is in place, so the bind follows."""
        ca = self.ca()
        _, d = self.start(tls=self.ldaps(ca, "require authc\n"), LDAP_OPT_X_TLS_CACERTFILE=ca.cert)
        self.assert_login(d, "PASS")

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_clear_text_warning(self):
        """A connection without TLS gives a warning on stderr before the bind; ldaps:// gives none."""
        log = self.capture_stderr("ldap")
        _, d = self.start()
        self.assert_login(d, "PASS")
        self.assert_clear_text_warning(log, True)
        ca = self.ca()
        log = self.capture_stderr("ldaps")
        _, d = self.start(tls=self.ldaps(ca), LDAP_OPT_X_TLS_CACERTFILE=ca.cert)
        self.assert_login(d, "PASS")
        self.assert_clear_text_warning(log, False)

    @unittest.skipUnless(LINUX, "the open files of the back-end are found through /proc")
    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_failed_starttls_closes_the_connection(self):
        """slapd closes the connection after the failed handshake; the back-end must close its socket too."""
        ca = self.ca()
        _, d = self.start(tls=self.ldaps(ca), starttls=True)
        self.assertEqual(self.login(d), "FAIL")
        before = backend_fds(d, "ldapmavis-mt")
        for _ in range(10):
            self.assertEqual(self.login(d), "FAIL")
        self.assertEqual(backend_fds(d, "ldapmavis-mt"), before)

    def test_request_without_a_user_name(self):
        """No or an empty user name: FAIL, and the backend answers the next request.

        tac_plus-ng sends no such request (see test_empty_user_name), so the
        test speaks the external-mt protocol to ldapmavis-mt itself.
        """
        slapd = self.slapd()
        env = {**sanitizer_env(), "LDAP_HOSTS": slapd.url, "LDAP_BASE": BASE, "LDAP_USER": READER,
               "LDAP_PASSWD": "readerpw"}
        with subprocess.Popen([LDAPMAVIS], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=env) as p:
            watchdog = threading.Timer(60, p.kill)
            watchdog.start()
            try:
                for user, result in ((None, b"NAK"), (b"", b"NAK"), (b"alice", b"ACK")):
                    body = (b"" if user is None else b"4 " + user + b"\n") + b"8 alicepw\n21 serial\n49 AUTH\n\n"
                    p.stdin.write(struct.pack("!III", 0x4d610001, len(body), 0) + body)
                    p.stdin.flush()
                    header = p.stdout.read(12)
                    self.assertEqual(len(header), 12, f"no reply for user {user!r}, the backend exited")
                    reply = p.stdout.read(struct.unpack("!III", header)[1])
                    self.assertRegex(reply, rb"(?m)^6 " + result + rb"$", user)
            finally:
                watchdog.cancel()
                p.kill()

    def test_wide_group_tree(self):
        """A user in more groups than the old fixed array of the group walk had; the last group still counts."""
        ldif = "".join(f"\ndn: cn=wide-{i},ou=groups,{BASE}\nobjectClass: groupOfNames\ncn: wide-{i}\n"
                       f"member: uid=wide,ou=people,{BASE}\n" for i in range(WIDE))
        _, d = self.start(ldif=person("wide") + ldif, LDAP_SIZELIMIT=str(2 * WIDE))
        with d.connect(timeout=30.0) as c:
            r = c.ascii_login("wide", "widepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "wide\n"), r)

    def test_wide_memberof_tree(self):
        """memberOf: the direct group of the user has WIDE parents, and only the last parent is in cn=wide-<last>."""
        last = f"cn=wide-{WIDE - 1},ou=groups,{BASE}"
        ldif = person("mowide", f"objectClass: extensibleObject\nmemberOf: cn=mo-direct,ou=groups,{BASE}\n")
        ldif += f"\ndn: cn=mo-direct,ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
        ldif += f"cn: mo-direct\nmember: cn=nobody,{BASE}\n"
        ldif += "".join(f"memberOf: cn=mo-{i},ou=groups,{BASE}\n" for i in range(WIDE))
        for i in range(WIDE):
            ldif += f"\ndn: cn=mo-{i},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: mo-{i}\nmember: cn=nobody,{BASE}\n" + (f"memberOf: {last}\n" if i == WIDE - 1 else "")
        _, d = self.start(ldif=ldif)
        with d.connect(timeout=30.0) as c:
            r = c.ascii_login("mowide", "mowidepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "wide\n"), r)


    def test_memberof_depth_order(self):
        """Depth 10, direct groups ord-a and ord-b: ord-a reaches ord-b at level 10, ord-b is in l3.

        l3 is two levels from the direct group ord-b, so both orders of the
        memberOf values must give l3.
        """
        chain = ["ord-a"] + [f"ord-{i}" for i in range(1, 9)] + ["ord-b", "l3"]
        ldif = ""
        for name, parent in zip(chain, chain[1:] + [None]):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: {name}\nmember: cn=nobody,{BASE}\n"
            ldif += f"memberOf: cn={parent},ou=groups,{BASE}\n" if parent else ""
        for user, first, second in (("ordab", "ord-a", "ord-b"), ("ordba", "ord-b", "ord-a")):
            ldif += person(user, f"objectClass: extensibleObject\nmemberOf: cn={first},ou=groups,{BASE}\n"
                                 f"memberOf: cn={second},ou=groups,{BASE}\n")
        _, d = self.start(ldif=ldif, LDAP_NESTED_GROUP_DEPTH="10")
        for user in ("ordab", "ordba"):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(user, user + "pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", "l3\n"), r)

    def test_ad_filter_after_a_failed_start(self):
        """The server is down at the start: the AD default filter comes with the first root DSE, LDAP_FILTER stays."""
        for env, status in (("", "PASS"), ('\t\tsetenv LDAP_FILTER = "(uid=%s)"\n', "FAIL")):
            with self.subTest(env=env):
                peer = AdPeer()
                self.addCleanup(peer.stop)
                module = (f'\tmavis module = external-mt {{\n\t\tsetenv LDAP_HOSTS = "{peer.url}"\n'
                          f'\t\tsetenv LDAP_BASE = "{BASE}"\n\t\tsetenv LDAP_USER = "{READER}"\n'
                          f'\t\tsetenv LDAP_PASSWD = "readerpw"\n{env}\t\texec = "{LDAPMAVIS}" "ldapmavis-mt"\n\t}}\n')
                # no authentication fallback: after the failed first login the daemon asks the backend again
                d = self.start_daemon(module + "\tuser backend = mavis\n\tpap backend = mavis\n"
                                               "\truleset { rule everyone { script { permit } } }\n")
                self.assertEqual(self.login(d), "FAIL")
                peer.down = False
                self.assertEqual(self.login(d), status)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_tls_client_certificate(self):
        """slapd demands a client certificate: LDAP_OPT_X_TLS_CERTFILE and LDAP_OPT_X_TLS_KEYFILE give it."""
        ca = self.ca()
        conf = self.ldaps(ca, "TLSVerifyClient demand\n")
        client = {"LDAP_OPT_X_TLS_CERTFILE": ca.client[0], "LDAP_OPT_X_TLS_KEYFILE": ca.client[1]}
        for env, status in (({}, "FAIL"), (client, "PASS")):
            with self.subTest(env=sorted(env)):
                _, d = self.start(tls=conf, LDAP_OPT_X_TLS_CACERTFILE=ca.cert, **env)
                self.assertEqual(self.login(d), status)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_tls_protocol_max(self):
        """slapd takes TLS 1.3 only: LDAP_OPT_X_TLS_PROTOCOL_MAX = TLS 1.2 (0x303) cannot connect."""
        ca = self.ca()
        conf = self.ldaps(ca, "TLSProtocolMin 3.4\n")
        for env, status in (({}, "PASS"), ({"LDAP_OPT_X_TLS_PROTOCOL_MAX": "0x303"}, "FAIL")):
            with self.subTest(env=env):
                if env and libldap_tls_package() == "GnuTLS":
                    self.skipTest("libldap with GnuTLS ignores LDAP_OPT_X_TLS_PROTOCOL_MAX")
                slapd, d = self.start(tls=conf, LDAP_OPT_X_TLS_CACERTFILE=ca.cert, **env)
                # TACTEST_PREFIX can give ldapmavis-mt another libldap than slapd
                if env and accepts_tls12(slapd.port):
                    self.skipTest("slapd accepts TLS 1.2: its libldap (GnuTLS) ignores TLSProtocolMin")
                self.assertEqual(self.login(d), status)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_tls_peerkey_hash(self):
        """LDAP_OPT_X_TLS_PEERKEY_HASH pins the key of the server: the right hash connects, another one does not."""
        ca = self.ca()
        der = subprocess.run(["openssl", "pkey", "-in", ca.server[1], "-pubout", "-outform", "DER"],
                             stdout=subprocess.PIPE, check=True).stdout
        right = "sha256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
        wrong = "sha256:" + base64.b64encode(hashlib.sha256(b"another key").digest()).decode()
        for pin, status in ((right, "PASS"), (wrong, "FAIL")):
            with self.subTest(pin=pin):
                _, d = self.start(tls=self.ldaps(ca), LDAP_OPT_X_TLS_CACERTFILE=ca.cert,
                                  LDAP_OPT_X_TLS_PEERKEY_HASH=pin)
                self.assertEqual(self.login(d), status)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_tls_context_error(self):
        """A TLS setting that libldap cannot load is a backend error: the global TLS context of libldap is not used."""
        ca = self.ca()
        # LDAPTLS_CACERT: the global TLS context of libldap trusts the server
        _, d = self.start(tls=self.ldaps(ca), LDAPTLS_CACERT=ca.cert,
                          LDAP_OPT_X_TLS_CACERTFILE=os.path.join(os.path.dirname(ca.cert), "no such ca.pem"))
        self.assertEqual(self.login(d), "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")

    def test_errors_close_the_connection(self):
        """A failed search (no such base) and a failed bind of LDAP_USER leave no connection to slapd open."""
        slapd, _ = self.start()
        for name, base, reader in (("search", "ou=missing," + BASE, READER), ("bind", BASE, "cn=nobody," + BASE)):
            with self.subTest(name):
                module = MODULE.substitute(module="external-mt", url=slapd.url, base=base, uid="%s",
                                           extra=setenv({"LDAP_USER": reader, "LDAP_PASSWD": "readerpw"}),
                                           exec=f'"{LDAPMAVIS}" "ldapmavis-mt"')
                d = self.start_daemon(POLICY.substitute(module=module, staff=STAFF, base=BASE, last=WIDE - 1),
                                      name=self.id().split(".")[-1] + "-" + name)
                self.assert_connections_closed(slapd, d)


@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
@unittest.skipUnless(shutil.which("ldd"), "no ldd")
class Libldap(unittest.TestCase):
    def test_without_development_files(self):
        """Without the development files of libldap, ctypes.util.find_library finds no libldap."""
        with unittest.mock.patch("ctypes.util.find_library", return_value=None):
            self.assertTrue(libldap_tls_package())


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerl(LdapTests, DaemonTestCase):
    CONFIG = None
    NO_CHECK = (("TLS_OPTIONS", "verify => 'none'"),)
    # StartTLS is mandatory by default; None keeps the LDAP_SKIP_STARTTLS=1 of start() away
    STARTTLS = {"LDAP_SKIP_STARTTLS": None}

    @staticmethod
    def TRUST(cafile):
        return {"TLS_OPTIONS": f"cafile => {perl_string(cafile)}"}

    # with a file name, the back-end writes its stderr there (see perl_exec())
    stderr_log = None

    def module(self, url, extra):
        return MODULE.substitute(module="external", url=url, base=BASE, uid="%s", extra=extra,
                                 exec=perl_exec(self, LDAP_PERL, self.stderr_log))

    def start(self, ldif="", policy="", tls="", starttls=False, root_dse="by * read", **env):
        """LdapTests.start(); a slapd without TLS gets LDAP_SKIP_STARTTLS=1, unless env sets it (None: not set)."""
        if not tls:
            env.setdefault("LDAP_SKIP_STARTTLS", "1")
        return super().start(ldif, policy, tls, starttls, root_dse, **env)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_by_default(self):
        """ldap://: StartTLS before all binds, also if the root DSE does not show StartTLS.

        A failed StartTLS is a backend error, and no bind follows (no StartTLS: see test_starttls_required).
        """
        ca = self.ca()
        refuse_clear = self.ldaps(ca, "security simple_bind=1\n")  # slapd refuses simple binds without TLS
        for root_dse in ("by * read", "by * none"):
            with self.subTest(root_dse=root_dse):
                slapd, d = self.start(tls=refuse_clear, starttls=True, root_dse=root_dse, **self.TRUST(ca.cert))
                self.assert_login(d, "PASS")
                self.assertTrue(slapd.binds())
                self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
        with self.subTest("CA not trusted"):
            slapd, d = self.start(tls=refuse_clear, starttls=True)
            for _ in range(2):  # the second request does not bind on the connection of the first one
                self.assert_login(d, "FAIL")
            self.assertEqual(slapd.binds(), [])

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_skip_starttls(self):
        """LDAP_SKIP_STARTTLS=1: the binds in clear text and a warning on stderr; ldaps:// keeps TLS, no warning."""
        self.stderr_log = self.scratch_file("skip.log", "")
        slapd, d = self.start(LDAP_SKIP_STARTTLS="1")
        self.assert_login(d, "PASS")
        self.assertIn((READER, False), slapd.binds())
        with open(self.stderr_log, errors="replace") as f:
            self.assertIn(CLEAR_TEXT_WARNING, f.read())
        ca = self.ca()
        self.stderr_log = self.scratch_file("ldaps.log", "")
        slapd, d = self.start(tls=self.ldaps(ca), LDAP_SKIP_STARTTLS="1", **self.TRUST(ca.cert))
        self.assert_login(d, "PASS")
        self.assertTrue(slapd.binds())
        self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
        with open(self.stderr_log, errors="replace") as f:
            self.assertNotIn(CLEAR_TEXT_WARNING, f.read())

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_after_a_reconnect(self):
        """slapd closes the idle connection: the new connection of the back-end starts TLS before its bind."""
        ca = self.ca()
        self.stderr_log = self.scratch_file("reconnect.log", "")
        slapd = self.slapd(tls=self.ldaps(ca, "security simple_bind=1\nidletimeout 1\n"), starttls=True)
        extra = setenv({"LDAP_USER": READER, "LDAP_PASSWD": "readerpw", **self.TRUST(ca.cert)})
        d = self.start_daemon(POLICY.substitute(module=self.module(slapd.url, extra + "\t\tchilds min = 1\n"
                                                                   "\t\tchilds max = 1\n"),
                                                staff=STAFF, base=BASE, last=WIDE - 1))
        self.assertEqual(self.login(d), "PASS")
        wait_for_idle_close(slapd)
        self.assertEqual(self.login(d), "PASS")
        with open(self.stderr_log, errors="replace") as f:  # one of the two reconnect paths
            self.assertRegex(f.read(), "ldap connection detected dead|ldap retry, due to bind failure")
        self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])

    def test_ad_root_dse(self):
        """The root DSE of AD: the server type is microsoft, and its default filter (sAMAccountName) finds alice."""
        peer = AdPeer()
        self.addCleanup(peer.stop)
        peer.down = False
        module = (f'\tmavis module = external {{\n\t\tsetenv LDAP_HOSTS = "{peer.url}"\n'
                  f'\t\tsetenv LDAP_BASE = "{BASE}"\n\t\tsetenv LDAP_USER = "{READER}"\n'
                  f'\t\tsetenv LDAP_PASSWD = "readerpw"\n\t\tsetenv LDAP_SKIP_STARTTLS = "1"\n'
                  f'\t\texec = "{PERL}" "perl" "{LDAP_PERL}"\n\t}}\n')
        d = self.start_daemon(module + "\tuser backend = mavis\n\tpap backend = mavis\n"
                                       "\truleset { rule everyone { script { permit } } }\n")
        self.assertEqual(self.login(d), "PASS")

    def test_no_root_dse_message(self):
        """Without the root DSE the back-end writes one line to stderr."""
        self.stderr_log = self.scratch_file("perl-ldap.log", "")
        _, d = self.start(root_dse=f'by dn.exact="{READER}" none by * read')
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        with open(self.stderr_log, errors="replace") as f:
            self.assertIn("no root DSE: the LDAP server type is generic", f.read())


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerlNoRootDse(DaemonTestCase):
    """mavis_tacplus_ldap.pl with LDAP_SERVER_TYPE = generic, and a root DSE that the user cannot read."""

    CONFIG = None

    def test_no_root_dse_password_change(self):
        """A server that does not give the root DSE to the user: the password change with the extension.

        Without the root DSE the back-end does not know if the server has the password modify extension. It must not
        write a crypt() hash: with a two-character salt only the first eight characters of the password count.
        """
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))),
                      root_dse=f'by dn.exact="uid=carol,ou=people,{BASE}" none by * read')
        self.addCleanup(slapd.stop)
        slapd.start()
        d = self.start_daemon(f"""
	mavis module = external {{
		setenv LDAP_SERVER_TYPE = "generic"
		setenv LDAP_HOSTS = "{slapd.url}"
		setenv LDAP_BASE = "{BASE}"
		setenv LDAP_USER = "{READER}"
		setenv LDAP_PASSWD = "readerpw"
		setenv FLAG_CHPW = "1"
		setenv LDAP_SKIP_STARTTLS = "1"
		exec = "{PERL}" "perl" "{LDAP_PERL_OLD}"
	}}
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	ruleset {{ rule {{ script {{ permit }} }} }}
""")
        with d.connect() as c:
            r = c.ascii_login("carol", "", data=["carolpw", "Abcdef12suffix", "Abcdef12suffix"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        for password, status in (("Abcdef12suffix", "PASS"), ("Abcdef12", "FAIL"), ("carolpw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("carol", password).status_name, status)


# mavis_tacplus_ldap.pl; one child, so a change of its state shows in its next request
MODULE_OLD = string.Template("""
	mavis module ldap = external {
		setenv LDAP_SERVER_TYPE = "tacacs_schema"
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_USER = "$reader"
		setenv LDAP_PASSWD = "readerpw"
		setenv LDAP_SKIP_STARTTLS = "1"
$extra		childs min = 1
		childs max = 1
		exec = "$perl" "perl" "$script"
	}
""")

POLICY_OLD = """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	ruleset { rule { script { permit } } }
"""


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerlTacacsSchema(DaemonTestCase):
    """mavis_tacplus_ldap.pl with LDAP_SERVER_TYPE = tacacs_schema; its default filter needs the tacacsAccount class."""

    CONFIG = None

    def start(self, stub=False, **env):
        """Start slapd and the daemon; stub: the stub back-end is the next MAVIS module."""
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))))
        self.addCleanup(slapd.stop)
        slapd.start()
        extra = "".join(f'\t\tsetenv {name} = "{value}"\n' for name, value in env.items())
        module = MODULE_OLD.substitute(url=slapd.url, base=BASE, reader=READER, extra=extra, perl=PERL,
                                       script=LDAP_PERL_OLD)
        return self.start_daemon(module + (Stub.module(childs=(1, 1)) if stub else "") + POLICY_OLD)

    def test_expired_password(self):
        """The password of frank expired (shadowExpire); alice has no tacacsAccount class."""
        d = self.start()
        for user, password, status in (("erin", "erinpw", "PASS"), ("erin", "wrong", "FAIL"),
                                       ("frank", "frankpw", "FAIL"), ("alice", "alicepw", "FAIL")):
            with self.subTest(user=user, password=password), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)

    def test_authorize_only(self):
        """FLAG_AUTHORIZE_ONLY: the back-end does not check the password, the next module does, in every request."""
        d = self.start(stub=True, FLAG_AUTHORIZE_ONLY="1")
        Stub(d).set(users={"erin": {"password": "stubpw"}, "frank": {"password": "stubpw"}})
        for user, password, status in (("erin", "wrong", "FAIL"), ("erin", "erinpw", "FAIL"),
                                       ("erin", "stubpw", "PASS"), ("frank", "stubpw", "PASS")):
            with self.subTest(user=user, password=password), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerlGeneric(DaemonTestCase):
    """mavis_tacplus_ldap.pl with LDAP_SERVER_TYPE = generic."""

    CONFIG = None

    def test_shadow_expire(self):
        """shadowExpire -1 does not expire (shadow(5)), shadowExpire 1 expired in 1970."""
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))))
        self.addCleanup(slapd.stop)
        slapd.start()
        d = self.start_daemon(f"""
	mavis module = external {{
		setenv LDAP_SERVER_TYPE = "generic"
		setenv LDAP_HOSTS = "{slapd.url}"
		setenv LDAP_BASE = "{BASE}"
		setenv LDAP_USER = "{READER}"
		setenv LDAP_PASSWD = "readerpw"
		setenv LDAP_SKIP_STARTTLS = "1"
		exec = "{PERL}" "perl" "{LDAP_PERL_OLD}"
	}}
	user backend = mavis
	pap backend = mavis
	ruleset {{ rule {{ script {{ permit }} }} }}
""")
        for user, password, status in (("grace", "gracepw", "PASS"), ("grace", "wrong", "FAIL"),
                                       ("heidi", "heidipw", "FAIL")):
            with self.subTest(user=user, password=password), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)


def new_slapd(case, **args):
    """A running slapd for a test that does not use LdapTests; args: see Slapd."""
    slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(case.scratch_file("slapd", ""))), **args)
    case.addCleanup(slapd.stop)
    slapd.start()
    return slapd


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerlOldStartTls(DaemonTestCase):
    """mavis_tacplus_ldap.pl with LDAP_SERVER_TYPE = generic: StartTLS on ldap:// URLs."""

    CONFIG = None

    def start(self, url, stderr_log=None, **env):
        """The daemon with mavis_tacplus_ldap.pl on url; stderr_log: see perl_exec(), env: for the back-end."""
        extra = "".join(f'\t\tsetenv {name} = "{value}"\n' for name, value in env.items())
        return self.start_daemon(f"""
	mavis module = external {{
		setenv LDAP_SERVER_TYPE = "generic"
		setenv LDAP_HOSTS = "{url}"
		setenv LDAP_BASE = "{BASE}"
		setenv LDAP_USER = "{READER}"
		setenv LDAP_PASSWD = "readerpw"
		setenv FLAG_CHPW = "1"
{extra}		childs min = 1
		childs max = 1
		exec = {perl_exec(self, LDAP_PERL_OLD, stderr_log)}
	}}
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	authentication fallback = permit
	user rescue {{
		fallback-only
		password pap = clear rescuepw
	}}
	ruleset {{ rule {{ script {{ permit }} }} }}
""")

    def assert_login(self, d, status):
        """alice gets status; the fallback-only user can log in only if it is the backend error (FAIL)."""
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, status)
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS" if status == "FAIL" else "FAIL")

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_by_default(self):
        """StartTLS before all binds, also on the new connection of a password change; no StartTLS: backend error."""
        ca = LdapTests.ca(self)
        with self.subTest("StartTLS"):
            slapd = new_slapd(self, tls=LdapTests.ldaps(ca, "security simple_bind=1\n"), starttls=True)
            d = self.start(slapd.url)
            self.assert_login(d, "PASS")
            with d.connect() as c:
                r = c.ascii_login("carol", "", data=["carolpw", "newpw", "newpw"])
            self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
            with d.connect() as c:
                self.assertEqual(c.pap("carol", "newpw").status_name, "PASS")
            self.assertIn(("uid=carol,ou=people," + BASE, True), slapd.binds())
            self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
        with self.subTest("no StartTLS"):
            slapd = new_slapd(self)
            self.assert_login(self.start(slapd.url), "FAIL")
            self.assertEqual(slapd.binds(), [])

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_after_a_reconnect(self):
        """FLAG_CACHE_CONNECTION, slapd closes the idle connection: the new connection starts TLS before its bind."""
        ca = LdapTests.ca(self)
        slapd = new_slapd(self, tls=LdapTests.ldaps(ca, "security simple_bind=1\nidletimeout 1\n"), starttls=True)
        d = self.start(slapd.url, FLAG_CACHE_CONNECTION="1")
        self.assert_login(d, "PASS")
        wait_for_idle_close(slapd)
        self.assert_login(d, "PASS")
        self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])

    def test_skip_starttls(self):
        """LDAP_SKIP_STARTTLS=1: the binds in clear text, and a warning on stderr."""
        log = self.scratch_file("perl-ldap-old.log", "")
        slapd = new_slapd(self)
        self.assert_login(self.start(slapd.url, log, LDAP_SKIP_STARTTLS="1"), "PASS")
        self.assertIn((READER, False), slapd.binds())
        with open(log, errors="replace") as f:
            self.assertIn(CLEAR_TEXT_WARNING, f.read())

    def test_failed_starttls_stops_the_connection(self):
        """After a failed StartTLS the next request makes a new connection, also with FLAG_CACHE_CONNECTION."""
        peer = StartTlsPeer()
        self.addCleanup(peer.stop)
        d = self.start(peer.url, FLAG_CACHE_CONNECTION="1")
        for _ in range(2):
            self.assert_login(d, "FAIL")
        self.assertGreaterEqual(peer.hellos, 2)
        self.assertEqual(peer.after_failure, [])


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerlAuthOnly(DaemonTestCase):
    """mavis_ldap_authonly.pl, through its standard input and output: StartTLS on ldap:// URLs."""

    CONFIG = None

    def results(self, url, count=1, **env):
        """The AV_A_RESULT of count logins of alice in one back-end process, and its stderr; env: for the back-end."""
        env = {**os.environ, "LDAP_HOSTS": url, "LDAP_BASE": BASE, "LDAP_USER": READER, "LDAP_PASSWD": "readerpw",
               **env}
        p = subprocess.run([PERL, LDAP_PERL_AUTHONLY], input=b"4 alice\n8 alicepw\n49 AUTH\n=\n" * count,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60, check=False)
        replies = p.stdout.decode().split("\n=")[:-1]
        return [dict(re.findall(r"(?m)^(\d+) (.*)$", r)).get("6") for r in replies], p.stderr.decode()

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_by_default(self):
        """StartTLS before all binds; a server without StartTLS is a backend error, and no bind follows."""
        ca = LdapTests.ca(self)
        slapd = new_slapd(self, tls=LdapTests.ldaps(ca, "security simple_bind=1\n"), starttls=True)
        self.assertEqual(self.results(slapd.url)[0], ["ACK"])
        self.assertTrue(slapd.binds())
        self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
        slapd = new_slapd(self)
        self.assertEqual(self.results(slapd.url)[0], ["ERR"])
        self.assertEqual(slapd.binds(), [])

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_starttls_after_a_reconnect(self):
        """FLAG_CACHE_CONNECTION, slapd closes the idle connection: the new connection starts TLS before its bind."""
        ca = LdapTests.ca(self)
        slapd = new_slapd(self, tls=LdapTests.ldaps(ca, "security simple_bind=1\nidletimeout 1\n"), starttls=True)
        env = {**os.environ, "LDAP_HOSTS": slapd.url, "LDAP_BASE": BASE, "LDAP_USER": READER,
               "LDAP_PASSWD": "readerpw", "FLAG_CACHE_CONNECTION": "1"}
        with subprocess.Popen([PERL, LDAP_PERL_AUTHONLY], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=env) as p:
            watchdog = threading.Timer(60, p.kill)
            watchdog.start()
            try:
                for i in range(2):
                    if i:
                        wait_for_idle_close(slapd)
                    p.stdin.write(b"4 alice\n8 alicepw\n49 AUTH\n=\n")
                    p.stdin.flush()
                    reply = b""
                    while not re.search(rb"(?m)^=\d+\n", reply):
                        line = p.stdout.readline()
                        self.assertTrue(line, "the back-end exited")
                        reply += line
                    self.assertRegex(reply, rb"(?m)^6 ACK$")
            finally:
                watchdog.cancel()
                p.kill()
        self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])

    def test_skip_starttls(self):
        """LDAP_SKIP_STARTTLS=1: the binds in clear text, and a warning on stderr."""
        slapd = new_slapd(self)
        results, stderr = self.results(slapd.url, LDAP_SKIP_STARTTLS="1")
        self.assertEqual(results, ["ACK"])
        self.assertIn((READER, False), slapd.binds())
        self.assertIn(CLEAR_TEXT_WARNING, stderr)

    def test_failed_starttls_stops_the_connection(self):
        """After a failed StartTLS the next request makes a new connection, also with FLAG_CACHE_CONNECTION."""
        peer = StartTlsPeer()
        self.addCleanup(peer.stop)
        self.assertEqual(self.results(peer.url, 2, FLAG_CACHE_CONNECTION="1")[0], ["ERR", "ERR"])
        self.assertGreaterEqual(peer.hellos, 2)
        self.assertEqual(peer.after_failure, [])


@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class PerlSkipStartTlsValue(unittest.TestCase):
    def test_invalid_value(self):
        """LDAP_SKIP_STARTTLS other than 0 or 1: the Perl back-ends do not start."""
        for script in (LDAP_PERL, LDAP_PERL_OLD, LDAP_PERL_AUTHONLY):
            for value in ("", "yes", "2"):
                with self.subTest(script=os.path.basename(script), value=value):
                    env = {**os.environ, "LDAP_HOSTS": "ldap://127.0.0.1:1", "LDAP_SKIP_STARTTLS": value}
                    p = subprocess.run([PERL, script], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, env=env, timeout=60, check=False)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertIn(f"invalid LDAP_SKIP_STARTTLS: '{value}' (0 or 1)", p.stderr.decode())


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(python_ldap3(), f"no ldap3 module for {PYTHON}")
class LdapPythonServerName(DaemonTestCase):
    """mavis_tacplus_ldap.py, through its standard input and output: the certificate check for an IP address URL."""

    CONFIG = None
    ENTRY = ("\ndn: uid=ivan,ou=people,$base\nobjectClass: inetOrgPerson\nobjectClass: posixAccount\nuid: ivan\n"
             "cn: Ivan\nsn: Ivan\nuidNumber: 1005\ngidNumber: 1005\nhomeDirectory: /home/ivan\nuserPassword: ivanpw\n")

    def result(self, url, tls_options):
        """The AV_A_RESULT of a login of ivan, and the stderr of the back-end."""
        env = {k: v for k, v in os.environ.items() if not k.startswith(("LDAP_", "TLS_", "FLAG_"))}
        env.update(LDAP_HOSTS=url, LDAP_BASE=BASE, LDAP_USER=READER, LDAP_PASSWD="readerpw", TLS_OPTIONS=tls_options)
        p = subprocess.run([PYTHON, LDAP_PYTHON], input=b"0 TACPLUS\n4 ivan\n8 ivanpw\n49 AUTH\n=\n",
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60, check=False)
        return dict(re.findall(r"(?m)^(\d+) (.*)$", p.stdout.decode())).get("6"), p.stderr.decode()

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_valid_names_for_an_ip_address_url(self):
        """An ldaps://127.0.0.1 URL: valid_names adds a DNS name of the certificate, and the CA check stays."""
        ca = LdapTests.ca(self)
        entries = string.Template(self.ENTRY).substitute(base=BASE)
        trusted = f"ca_certs_file={ca.cert!r}"
        # the default certificate has IP:127.0.0.1 and DNS:localhost
        slapd = new_slapd(self, tls=LdapTests.ldaps(ca), entries=entries)
        self.assertTrue(slapd.url.startswith("ldaps://127.0.0.1:"), slapd.url)
        status, stderr = self.result(slapd.url, trusted)
        self.assertEqual(status, "ACK" if ldap3_matches_ip() else "ERR", stderr)
        cert, key = ca.issue("dns-only", "/O=tactest/CN=localhost", server=True, san="DNS:localhost")
        conf = (f"TLSCACertificateFile {slapd_arg(ca.cert)}\nTLSCertificateFile {slapd_arg(cert)}\n"
                f"TLSCertificateKeyFile {slapd_arg(key)}\n")
        slapd = new_slapd(self, tls=conf, entries=entries)
        cases = ((trusted, "ERR"),
                 (f"{trusted}, valid_names=['localhost']", "ACK"),
                 (f"{trusted}, valid_names=['ldap.example.org']", "ERR"),
                 ("valid_names=['localhost']", "ERR"))
        for options, status in cases:
            with self.subTest(options=options):
                result, stderr = self.result(slapd.url, options)
                self.assertEqual(result, status, stderr)


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(python_ldap3(), f"no ldap3 module for {PYTHON}")
class LdapPython(LdapTests, DaemonTestCase):
    """mavis_tacplus_ldap.py; slapd with "security simple_bind=1" refuses simple binds without TLS."""
    CONFIG = None
    NO_CHECK = (("TLS_OPTIONS", "validate=ssl.CERT_NONE"),)
    # StartTLS is mandatory by default; None keeps the LDAP_SKIP_STARTTLS=1 of start() away
    STARTTLS = {"LDAP_SKIP_STARTTLS": None}
    exe = None
    SCOPES = ("SUBTREE", "LEVEL", "BASE")

    def module(self, url, extra):
        command = f'"{self.exe}" "python3"' if self.exe else f'"{PYTHON}" "python3" "{LDAP_PYTHON}"'
        return MODULE.substitute(module="external", url=url, base=BASE, uid="{}", extra=extra,
                                 exec=command)

    @unittest.skip("the groupOfNames walk of the Python back-end does not escape the group DN in its filter")
    def test_filter_characters_in_a_group_dn(self):
        pass

    @unittest.skip("the groupOfNames walk of the Python back-end gives no groups for LDAP_NESTED_GROUP_DEPTH=1")
    def test_group_depth(self):
        pass

    @unittest.skip("without the root DSE the Python back-end does not use the generic server type")
    def test_no_root_dse(self):
        pass

    @staticmethod
    def TRUST(cafile):
        # ldap3 compares only the DNS names of the certificate with the host
        return {"TLS_OPTIONS": f"ca_certs_file={cafile!r}, valid_names=['localhost']"}

    def start(self, ldif="", policy="", tls="", *, starttls_default=False, **kwargs):
        """See LdapTests.start(); a slapd without TLS gets LDAP_SKIP_STARTTLS=1, unless starttls_default is set."""
        if not tls and not starttls_default:
            kwargs.setdefault("LDAP_SKIP_STARTTLS", "1")
        return super().start(ldif, policy, tls, **kwargs)

    def capture_stderr(self, name):
        """The next start() runs the back-end through a script that writes its stderr to the file name.

        MAVIS logs the stderr of the back-end to syslog only.
        """
        log = self.scratch_file(name + ".log", "")
        self.exe = self.scratch_file(name + ".sh", f'#!/bin/sh\nexec "{PYTHON}" "{LDAP_PYTHON}" 2>>"{log}"\n')
        os.chmod(self.exe, 0o755)
        return log

    def count_connections(self, name):
        """The next start() runs the back-end through COUNT_CONNECTIONS; returns count(d).

        count(d) is the number of ldap3.Connection objects in the back-end of daemon d.
        """
        out = self.scratch_file(name + ".count", "")
        os.remove(out)
        script = self.scratch_file(name + ".py", COUNT_CONNECTIONS)
        self.exe = self.scratch_file(name + ".sh", f'#!/bin/sh\nexec "{PYTHON}" "{script}" "{LDAP_PYTHON}" "{out}"\n')
        os.chmod(self.exe, 0o755)

        def count(d):
            os.kill(backend_pid(d, LDAP_PYTHON), signal.SIGUSR1)
            deadline = time.monotonic() + 10
            while not os.path.exists(out):
                if time.monotonic() > deadline:
                    raise AssertionError("the back-end did not count its connections")
                time.sleep(0.1)
            with open(out) as f:
                n = int(f.read())
            os.remove(out)
            return n
        return count

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
    def test_starttls_default(self):
        """ldap://: StartTLS before all binds, also if the root DSE does not offer it; a failure is a backend error."""
        ca = self.ca()
        refuse_clear = self.ldaps(ca, "security simple_bind=1\n")
        # anonymous clients do not see the root DSE, so it does not offer StartTLS to them
        hidden = self.ldaps(ca, 'security simple_bind=1\naccess to dn.base="" by users read by * none\n')
        cases = (("CA not trusted", refuse_clear, {}, "FAIL"),
                 ("CA trusted", refuse_clear, self.TRUST(ca.cert), "PASS"),
                 ("root DSE hidden, CA not trusted", hidden, {}, "FAIL"),
                 ("root DSE hidden", hidden, self.TRUST(ca.cert), "PASS"))
        for i, (name, slapd_tls, env, status) in enumerate(cases):
            with self.subTest(name):
                log = self.capture_stderr(f"default-{i}")
                slapd, d = self.start(tls=slapd_tls, starttls=True, **env)
                self.assert_login(d, status)
                if status == "FAIL":
                    self.assertEqual(slapd.binds(), [])
                    self.assertIn("StartTLS: ", self.stderr(log))
                else:
                    self.assertTrue(slapd.binds())
                    self.assertEqual([dn for dn, over_tls in slapd.binds() if not over_tls], [])
                self.assertNotIn(CLEAR_TEXT_WARNING, self.stderr(log))
        for name, env in (("no StartTLS on the server", {}), ("LDAP_SKIP_STARTTLS=0", {"LDAP_SKIP_STARTTLS": "0"})):
            with self.subTest(name):
                log = self.capture_stderr("plain" + "-0" * bool(env))
                slapd, d = self.start(starttls_default=True, **env)
                self.assert_login(d, "FAIL")
                self.assertEqual(slapd.binds(), [])
                self.assertIn("StartTLS: ", self.stderr(log))

    @unittest.skip("this back-end does not read USE_STARTTLS: see test_starttls_default and test_skip_starttls")
    def test_starttls_required(self):
        pass

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_skip_starttls(self):
        """LDAP_SKIP_STARTTLS=1 sends the binds in clear text, with a warning; USE_STARTTLS does not change that."""
        ca = self.ca()
        for name, env in (("LDAP_SKIP_STARTTLS", {}), ("USE_STARTTLS", {"USE_STARTTLS": "1"})):
            with self.subTest(name):
                log = self.capture_stderr(name)
                slapd, d = self.start(tls=self.ldaps(ca), starttls=True, LDAP_SKIP_STARTTLS="1", **env)
                self.assert_login(d, "PASS")
                self.assertIn((READER, False), slapd.binds())
                self.assertIn(CLEAR_TEXT_WARNING, self.stderr(log, CLEAR_TEXT_WARNING))

    def test_starttls_without_offer(self):
        """A failed StartTLS also without an offer in the root DSE: StartTLS is the only operation.

        LDAP_HOSTS without a URL scheme is ldap:// too.
        """
        for scheme in ("ldap://", ""):
            with self.subTest(scheme=scheme):
                peer = StartTlsPeer(offer=False)
                self.addCleanup(peer.stop)
                url = scheme + peer.url[len("ldap://"):]
                # with LDAP_USER: a bind as LDAP_USER before StartTLS would show in peer.ops
                extra = setenv({"LDAP_USER": READER, "LDAP_PASSWD": "readerpw"})
                d = self.start_daemon(POLICY.substitute(module=self.module(url, extra), staff=STAFF, base=BASE,
                                                        last=WIDE - 1))
                for _ in range(2):
                    self.assert_login(d, "FAIL")
                self.assertGreaterEqual(peer.hellos, 2)
                # no bind, search or other extended request before or after StartTLS; 0x42 is unbind
                self.assertEqual(set(peer.ops) - {0x42}, {"1.3.6.1.4.1.1466.20037"})
                self.assertEqual(peer.after_failure, [])

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_ca_path_with_quotes(self):
        """ca_certs_file keeps a CA path with quotes and a backslash: TLS_OPTIONS is Python source."""
        ca = tls.CA("it's \"a\" \\t")
        self.addCleanup(ca.remove)
        _, d = self.start(tls=self.ldaps(ca), **self.TRUST(ca.cert))
        self.assert_login(d, "PASS")

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_clear_text_warning(self):
        """A connection without TLS gives a warning on stderr before the bind; ldaps:// gives none."""
        log = self.capture_stderr("ldap")
        _, d = self.start()
        self.assert_login(d, "PASS")
        self.assertIn(CLEAR_TEXT_WARNING, self.stderr(log, CLEAR_TEXT_WARNING))
        ca = self.ca()
        log = self.capture_stderr("ldaps")
        slapd, d = self.start(tls=self.ldaps(ca), **self.TRUST(ca.cert))
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

    @unittest.skipUnless(LINUX, "the back-end process is found through /proc")
    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_failed_starttls_frees_the_connection(self):
        """Each login after a failed StartTLS makes a new connection; the back-end must not keep the old ones."""
        count = self.count_connections("count")
        ca = self.ca()
        _, d = self.start(tls=self.ldaps(ca), starttls=True)
        self.assertEqual(self.login(d), "FAIL")
        before = count(d)
        for _ in range(10):
            self.assertEqual(self.login(d), "FAIL")
        self.assertEqual(count(d), before)

    @unittest.skipUnless(tls.openssl_available(), "the certificates need the openssl command")
    def test_reconnect_starts_tls(self):
        """After slapd restarts, the back-end opens a new connection: StartTLS comes before its bind too."""
        ca = self.ca()
        log = self.capture_stderr("reconnect")
        # after a backend error, only fallback-only users can log in for this period
        slapd, d = self.start(tls=self.ldaps(ca, "security simple_bind=1\n"), starttls=True,
                              settings="authentication fallback period = 1\n", **self.TRUST(ca.cert))
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
        """Without LDAP_USER the back-end searches anonymously; a failed or a good login must not change that."""
        slapd, d = self.start(access=ANONYMOUS_ONLY, LDAP_USER=None, LDAP_PASSWD=None)
        logins = (("alice", "wrong", "FAIL"), ("bob", "bobpw", "PASS"), ("dave", "davepw", "PASS"))
        for user, password, status in logins:
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        self.assertEqual([dn for dn, _ in slapd.binds()], [ALICE, BOB, DAVE])

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

    def test_wrong_password_before_group_walk(self):
        """A wrong password is a FAIL before the group walk: a group search that fails does not change the answer."""
        # ldap3 refuses this filter (no closing parenthesis) with an exception, and sends no search
        _, d = self.start(LDAP_FILTER_GROUP="(member={}")
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "wrong").status_name, "FAIL")
        # no backend error: the fallback-only user cannot log in
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")

    def test_group_search_error(self):
        """A group search that fails after a good password is a backend error; the next request gets an answer."""
        log = self.capture_stderr("group-search")
        # after a backend error, only fallback-only users can log in for this period; the FAIL reply comes 1 s late
        slapd, d = self.start(settings="authentication fallback period = 3\n", LDAP_FILTER_GROUP="(member={}")
        self.assert_login(d, "FAIL")
        self.assertIn("invalid filter", self.stderr(log, "invalid filter"))
        before = len(slapd.binds())
        select.select([], [], [], 4)
        # not a backend error: the back-end binds as LDAP_USER again, finds bob and checks the password
        for user, password in (("bob", "wrong"), ("rescue", "rescuepw")):
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, "FAIL")
        self.assertEqual([dn for dn, _ in slapd.binds()[before:]], [READER, BOB])

    def test_password_change_after_group_walk(self):
        """The password change comes after the group walk: if a group search fails, the password does not change."""
        slapd, d = self.start(LDAP_FILTER_GROUP="(member={}")
        with d.connect() as c:
            r = c.ascii_login("carol", "", data=["carolpw", "newpw", "newpw"])
        self.assertEqual(r.statuses[-1], "FAIL", r)
        # a backend error: the fallback-only user can log in
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")
        # slapd -d 256 logs each extended operation with its OID: this one is the password modify (RFC 3062)
        with open(slapd.log, errors="replace") as f:
            self.assertNotIn("oid=1.3.6.1.4.1.4203.1.11.1", f.read())

    def test_no_referrals(self):
        """The back-end does not follow a referral: ldap3 binds to the referral host with the credentials it has."""
        with socket.socket() as host:
            host.bind(("127.0.0.1", 0))
            host.listen()
            # slapd answers a search base outside its suffix with this referral
            referral = f"\nreferral ldap://127.0.0.1:{host.getsockname()[1]}/"
            _, d = self.start(access=ACCESS + referral, LDAP_BASE_GROUP="dc=elsewhere,dc=org")
            for password, status in (("wrong", "FAIL"), ("alicepw", "PASS")):
                with self.subTest(password=password), d.connect() as c:
                    self.assertEqual(c.pap("alice", password).status_name, status)
            if select.select([host], [], [], 0)[0]:
                peer, _ = host.accept()
                with peer:
                    peer.settimeout(1)
                    self.fail(f"the back-end followed the referral and sent: {peer.recv(4096)!r}")

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

    def test_krb_password_expiration_format(self):
        """A krbPasswordExpiration that is not YYYYMMDDHHMMSSZ gives no expiry; the back-end continues."""
        schema = ("attributetype ( 2.16.840.1.113719.1.301.4.6.1 NAME 'krbPasswordExpiration' "
                  "EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )")
        # a generalized time with a time zone offset
        kurt = person("kurt", "objectClass: extensibleObject\nkrbPasswordExpiration: 20991231235959+0100\n")
        _, d = self.start(access=ACCESS + "\n" + schema, ldif=kurt)
        for password, status in (("kurtpw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("kurt", password).status_name, status)
        # no backend error: the fallback-only user cannot log in
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")

    def test_starttls_settings_invalid(self):
        """A LDAP_SKIP_STARTTLS that is not 0 or 1 stops the back-end."""
        cases = tuple(({"LDAP_SKIP_STARTTLS": value}, f"invalid LDAP_SKIP_STARTTLS: {value!r}")
                      for value in ("yes", "", "2", "-1", " 1"))
        for i, (env, message) in enumerate(cases):
            with self.subTest(env=env):
                log = self.capture_stderr(f"invalid-{i}")
                # check=False: the back-end exits on purpose
                self.start(check=False, **env)
                self.assertIn(message, self.stderr(log, message))
                # the exit status, not only the message: the back-end must not go on
                clean = {k: v for k, v in os.environ.items() if not k.startswith(("LDAP_", "TLS_", "FLAG_"))}
                p = subprocess.run([PYTHON, LDAP_PYTHON], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, env={**clean, "LDAP_HOSTS": "ldap://127.0.0.1:1", **env},
                                   timeout=60, check=False)
                self.assertNotEqual(p.returncode, 0, p.stderr.decode())
                self.assertIn(message, p.stderr.decode())


if __name__ == "__main__":
    unittest.main()
