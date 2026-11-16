# Run as root. Can another user bind the UDP address and port of a root listener that has
# the socket options of spawnd? spawnd: SO_REUSEADDR everywhere; SO_REUSEPORT on the BSDs (change under test).
import os, pwd, socket, sys, time

PORT = 41812
LINUX = sys.platform.startswith("linux")

def sock(reuseport):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuseport:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return s

listener = sock(not LINUX)
listener.bind(("127.0.0.1", PORT))
print("listener uid=0 REUSEADDR%s bound" % ("" if LINUX else "+REUSEPORT"))
for user in ("root", "nobody"):
    for reuseport in (False, True):
        pid = os.fork()
        if pid == 0:
            if user == "nobody":
                pw = pwd.getpwnam("nobody")
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
            s = sock(reuseport)
            try:
                s.bind(("127.0.0.1", PORT))
                r = "bind OK"
            except OSError as e:
                r = "bind FAILED: %s" % e
            print("other uid=%d REUSEADDR%s: %s" % (os.geteuid(), "+REUSEPORT" if reuseport else "", r), flush=True)
            os._exit(0)
        os.waitpid(pid, 0)
