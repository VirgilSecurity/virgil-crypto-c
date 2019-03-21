import unittest

from virgil_crypto.phe import Client
from virgil_crypto.phe import Server


class ServerTest(unittest.TestCase):

    def test_generate_keypair(self):
        s = Server()
        priv_key, pub_key = s.generate_server_keypair()
        self.assertIsNotNone(priv_key)
        self.assertIsNotNone(pub_key)
        self.assertIsInstance(priv_key, bytearray)
        self.assertIsInstance(pub_key, bytearray)

    def test_get_enrollment(self):
        s = Server()
        priv_key, pub_key = s.generate_server_keypair()
        enroll = s.get_enrollment(priv_key, pub_key)
        self.assertIsNotNone(enroll)
        self.assertIsInstance(enroll, bytearray)

    def test_verify_password(self):
        s = Server()
        c = Client()
        server_private_key, server_public_key = s.generate_server_keypair()
        client_private_key, client_public_key = s.generate_server_keypair()
        enrollment_response = s.get_enrollment(server_private_key, server_public_key)

        record, enroll_key = c.enroll_account(
            client_private_key,
            server_public_key,
            enrollment_response,
            bytearray("passw0rd".encode()),
        )
        request = c.password_verify_request(
            client_private_key,
            server_public_key,
            record,
            bytearray("passw0rd".encode())
        )

        response = s.verify_password(server_private_key, server_public_key, request)
        self.assertIsNotNone(response)
        self.assertIsInstance(response, bytearray)
