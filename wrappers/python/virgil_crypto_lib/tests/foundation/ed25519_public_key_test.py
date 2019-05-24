import unittest

from virgil_crypto_lib.foundation import Ed25519PublicKey
from virgil_crypto_lib.foundation._c_bridge import VscfAlgId
from virgil_crypto_lib.tests.data.test_data import TestData


class Ed25519PublicKeyTest(unittest.TestCase):

    def test_key_len_imported_public_key(self):
        public_key = Ed25519PublicKey()
        public_key.setup_defaults()

        public_key.import_public_key(TestData.ED25519_PUBLIC_KEY)

        self.assertEqual(32, public_key.key_len())

    def test_export_public_key_from_imported_public_key(self):
        public_key = Ed25519PublicKey()
        public_key.setup_defaults()

        public_key.import_public_key(TestData.ED25519_PUBLIC_KEY)

        exported_key = public_key.export_public_key()

        self.assertEqual(TestData.ED25519_PUBLIC_KEY, exported_key)

    def test_verify_with_imported_public_key_and_data_signature(self):
        public_key = Ed25519PublicKey()
        public_key.setup_defaults()

        public_key.import_public_key(TestData.ED25519_PUBLIC_KEY)

        verify_result = public_key.verify_hash(TestData.ED25519_MESSAGE_SHA256_DIGEST, VscfAlgId.SHA256, TestData.ED25519_SHA256_SIGNATURE)
        self.assertTrue(verify_result)

    def test_encrypt_message_with_imported_key(self):
        public_key = Ed25519PublicKey()
        public_key.setup_defaults()

        public_key.import_public_key(TestData.ED25519_PUBLIC_KEY)

        try:
            encrypted_message = public_key.encrypt(TestData.ED25519_MESSAGE)
        except Exception:
            self.fail("test_encrypt_message_with_imported_key raised Exception unexpectedly!")

        self.assertIsNotNone(encrypted_message)
