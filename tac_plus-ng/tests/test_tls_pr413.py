"""Checks for the #413 preview: client certificates the device selection must survive."""

import unittest

from tactest import tacacs
from test_tls import TLS_REALM, TlsTestCase, policy


class PeerCertWithoutCn(TlsTestCase):
    """A client certificate without a CN whose SAN and subject select no device: the address does."""

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + """
	device xr {
		address = 127.0.0.65
		key = xrkey
	}
""" + policy(("xr", "localhost"))
    CLIENTS = {
        "no_cn": ("/O=tactest/serialNumber=e3d752c5", "DNS:nothing.tactest.invalid"),
        "no_cn_no_san": "/O=tactest/serialNumber=e3d752c6",
    }

    def device(self, client, source="127.0.0.65"):
        c = self.connect_tls(client, source=source)
        self.assertTrue(c.pap("alice", "alicepw").ok)
        return self.device_and_transport(c)["tactest-device"]

    def test_no_cn_dns_san_selects_nothing(self):
        self.assertEqual(self.device("no_cn"), "xr")

    def test_no_cn_no_san(self):
        self.assertEqual(self.device("no_cn_no_san"), "xr")

    def test_worker_alive_afterwards(self):
        for client in ("no_cn", "no_cn_no_san"):
            try:
                self.device(client)
            except Exception:
                pass
        self.assertEqual(self.device("no_cn"), "xr")


if __name__ == "__main__":
    unittest.main()
