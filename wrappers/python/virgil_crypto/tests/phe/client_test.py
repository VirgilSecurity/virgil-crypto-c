import unittest

from virgil_crypto.phe import Client
from virgil_crypto.phe import Server


class ClientTest(unittest.TestCase):

    def test_enroll_account(self):
        s = Server()
        c = Client()
        server_private_key, server_public_key = s.generate_server_keypair()
        client_private_key, client_public_key = s.generate_server_keypair()
        enrollment_response = s.get_enrollment(server_private_key, server_public_key)
        enroll_record, enroll_key = c.enroll_account(
            client_private_key,
            server_public_key,
            enrollment_response,
            bytearray("passw0rd".encode())
        )
        self.assertIsNotNone(enroll_record)
        self.assertIsNotNone(enroll_key)
        self.assertIsInstance(enroll_record, bytearray)
        self.assertIsInstance(enroll_key, bytearray)

    def test_password_verify_request(self):
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
        self.assertIsNotNone(request)
        self.assertIsInstance(request, bytearray)

    def test_verify_server_response(self):
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

        verified_response = c.verify_server_response(
            client_private_key,
            server_public_key,
            bytearray("passw0rd".encode()),
            record,
            response
        )

        self.assertIsNotNone(verified_response)
        self.assertIsInstance(verified_response, bytearray)
