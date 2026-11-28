"""RADIUS PAP requests rejected by the MAVIS backend."""

from tactest import DaemonTestCase, Stub
from test_radius import DICTIONARY, NAS, SECRET


class MavisPapRejection(DaemonTestCase):
    CONFIG = Stub.module() + f"""
	include = "{DICTIONARY}"
	user backend = mavis
	login backend = mavis
	ruleset {{ rule {{ script {{ permit }} }} }}
	device radius-nas {{
		address = {NAS}
		key = tactest
		radius.key = {SECRET}
	}}
"""

    def test_rejects_uncached_backend_user(self):
        stub = Stub(self.daemon)
        stub.set(users={"backend-only": {"password": "correct-password"}})
        reply = self.radius(SECRET, source=NAS, tcp=True).access_request(
            "backend-only", "rejected-sample-password", message_authenticator=True
        )
        self.assertEqual(reply.code_name, "Access-Reject")
        self.assertEqual([entry["result"] for entry in stub.requests("AUTH", "backend-only")], ["NAK"])
