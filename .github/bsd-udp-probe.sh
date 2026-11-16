#!/bin/sh
# Probe: one failing RADIUS/UDP test, with a packet capture and a system call trace.
P=$PWD/build/probe
mkdir -p "$P"
uname -a > "$P/uname.txt"
grep -n 'IP_PKTINFO\|IP_RECVDSTADDR\|IP_SENDSRCADDR\|IPV6_RECVPKTINFO\|define[[:space:]]IPV6_PKTINFO\|IP_RECVIF\|IP_BINDANY\|SO_REUSEPORT' \
	/usr/include/netinet/in.h /usr/include/netinet6/in6.h /usr/include/sys/socket.h > "$P/headers.txt" 2>&1
LO=lo0; [ "$(uname -s)" = Linux ] && LO=lo
sh tac_plus-ng/tests/loopback-aliases > "$P/aliases.txt" 2>&1
(ifconfig $LO || ip addr show dev lo) > "$P/lo0.txt" 2>&1
tac_plus-ng/tests/run-tests --build-only > "$P/build.txt" 2>&1 || { echo "build failed"; exit 0; }
TACTEST_PREFIX=$(echo "$PWD"/build/*/tests-prefix)
export TACTEST_PREFIX TACTEST_KEEP=1 TACTEST_WORKDIR=$P/work
T=test_radius.PapOverIpv6.test_access_accept
tcpdump -i $LO -n -l -vv udp > "$P/tcpdump.txt" 2>&1 &
TP=$!
sleep 2
case $(uname -s) in
FreeBSD)
	truss -f -o "$P/trace.txt" tac_plus-ng/tests/run-tests -k "$T" > "$P/test.txt" 2>&1 ;;
Linux)
	strace -f -e trace=network,write -o "$P/trace.txt" tac_plus-ng/tests/run-tests -k "$T" > "$P/test.txt" 2>&1 ;;
OpenBSD)
	ktrace -i -f "$P/ktrace.out" tac_plus-ng/tests/run-tests -k "$T" > "$P/test.txt" 2>&1
	kdump -n -f "$P/ktrace.out" > "$P/trace.txt" 2>&1
	rm -f "$P/ktrace.out" ;;
esac
sleep 1
kill $TP
netstat -an -p udp > "$P/netstat.txt" 2>&1 || netstat -an -f inet > "$P/netstat.txt" 2>&1
ls -la "$P"
exit 0
