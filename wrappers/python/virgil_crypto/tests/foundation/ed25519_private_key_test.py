import unittest
from binascii import unhexlify, hexlify

from virgil_crypto.foundation import Ed25519PrivateKey, FakeRandom
from virgil_crypto.foundation._c_bridge import VscfAlgId
from virgil_crypto.tests.data.test_data import TestData


class Ed25519PrivateKeyTest(unittest.TestCase):

    def test_key_len_imported_private_key(self):
        private_key = Ed25519PrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.ED25519_PRIVATE_KEY)
        self.assertEqual(32, private_key.key_len())

    def test_export_private_key_from_imported_private_key(self):
        private_key = Ed25519PrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.ED25519_PRIVATE_KEY)
        exported_key = private_key.export_private_key()

        self.assertEqual(TestData.ED25519_PRIVATE_KEY, exported_key)

    def test_extract_public_key_from_imported_private_key(self):
        private_key = Ed25519PrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.ED25519_PRIVATE_KEY)
        public_key = private_key.extract_public_key()

        exported_public_key = public_key.export_public_key()

        self.assertEqual(TestData.ED25519_PUBLIC_KEY, exported_public_key)

    def test_sign_with_imported_private_key_and_message(self):
        private_key = Ed25519PrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.ED25519_PRIVATE_KEY)

        signature = private_key.sign_hash(TestData.ED25519_MESSAGE_SHA256_DIGEST, VscfAlgId.SHA256)

        self.assertEqual(TestData.ED25519_SHA256_SIGNATURE, signature)

    def test_export_private_key_with_imported_ed25519_private_key(self):
        private_key = Ed25519PrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.ED25519_PRIVATE_KEY)

        exported_key = private_key.export_private_key()
        self.assertEqual(TestData.ED25519_PRIVATE_KEY, exported_key)

    def test_generate_key_and_export_private_key(self):
        private_key = Ed25519PrivateKey()

        fake_random = FakeRandom()
        fake_random.setup_source_data(TestData.ED25519_RANDOM)

        private_key.set_random(fake_random)
        private_key.setup_defaults()

        private_key.generate_key()

        exported_key = private_key.export_private_key()

        self.assertEqual(bytearray(TestData.ED25519_PRIVATE_KEY), exported_key)

    def test_decrypt_message_with_imported_key(self):
        private_key = Ed25519PrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.ED25519_PRIVATE_KEY)

        decrypted_message = private_key.decrypt(TestData.ED25519_ENCRYPTED_MESSAGE)

        self.assertEqual(TestData.ED25519_MESSAGE, decrypted_message)
