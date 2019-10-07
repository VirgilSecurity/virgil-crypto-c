import unittest

from virgil_crypto_lib.phe import Client
from virgil_crypto_lib.phe import Server


class ServerTest(unittest.TestCase):

    def test_generate_keypair(self):
        s = Server()
        s.setup_defaults()
        priv_key, pub_key = s.generate_server_key_pair()
        self.assertIsNotNone(priv_key)
        self.assertIsNotNone(pub_key)
        self.assertIsInstance(priv_key, bytearray)
        self.assertIsInstance(pub_key, bytearray)

    def test_get_enrollment(self):
        s = Server()
        s.setup_defaults()
        priv_key, pub_key = s.generate_server_key_pair()
        enroll = s.get_enrollment(priv_key, pub_key)
        self.assertIsNotNone(enroll)
        self.assertIsInstance(enroll, bytearray)

    def test_verify_password(self):
        s = Server()
        c = Client()
        s.setup_defaults()
        c.setup_defaults()
        server_private_key, server_public_key = s.generate_server_key_pair()
        client_private_key, client_public_key = s.generate_server_key_pair()
        c.set_keys(client_private_key, server_public_key)
        enrollment_response = s.get_enrollment(server_private_key, server_public_key)

        record, enroll_key = c.enroll_account(
            enrollment_response,
            bytearray("passw0rd".encode()),
        )
        request = c.create_verify_password_request(
            bytearray("passw0rd".encode()),
            record
        )

        response = s.verify_password(server_private_key, server_public_key, request)
        self.assertIsNotNone(response)
        self.assertIsInstance(response, bytearray)
