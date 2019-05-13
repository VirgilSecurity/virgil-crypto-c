import unittest

from virgil_crypto.common._c_bridge import Data
from virgil_crypto.foundation import KeyProvider, KeyMaterialRng
from virgil_crypto.foundation._c_bridge import VscfAlgId
from virgil_crypto.tests.data import TestData


class KeyProviderTest(unittest.TestCase):

    def test_generate_private_key_ed25519(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)

        self.assertIsNotNone(private_key)

        self.assertEqual(VscfAlgId.ED25519, private_key.alg_id())
        self.assertEqual(256, private_key.key_bitlen())

    def test_generate_private_key_ed25519_and_then_do_encrypt_decrypt(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)

        public_key = private_key.extract_public_key()

        plain_message = "test data"
        encrypted_data = public_key.encrypt(plain_message)

        decrypted_data = private_key.decrypt(encrypted_data)

        self.assertEqual(plain_message, decrypted_data.decode())

    def test_generate_private_key_ed25519_and_then_do_sign_hash_and_verify_hash(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)
        public_key = private_key.extract_public_key()

        signature = private_key.sign_hash(TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST, VscfAlgId.SHA512)

        verified = public_key.verify_hash(TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST, VscfAlgId.SHA512, signature)
        self.assertTrue(verified)

    def test_generate_private_key_ed25519_with_key_material_rng(self):
        key_material_rng = KeyMaterialRng()
        key_material_rng.reset_key_material(TestData.DETERMINISTIC_KEY_KEY_MATERIAL)

        key_provider = KeyProvider()
        key_provider.set_random(key_material_rng)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)
        self.assertIsNotNone(private_key)

        exported_private_key = private_key.export_private_key()

        self.assertIsNotNone(exported_private_key)
        self.assertEqual(TestData.DETERMINISTIC_KEY_ED25519_PRIVATE_KEY, exported_private_key)

    def test_generate_private_key_rsa_2048(self):
        key_provider = KeyProvider()
        key_provider.set_rsa_params(2048)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)

        self.assertIsNotNone(private_key)
        self.assertEqual(VscfAlgId.RSA, private_key.alg_id())
        self.assertEqual(2048, private_key.key_bitlen())

    def test_generate_private_key_rsa_2048_and_then_do_encrypt_decrypt(self):
        key_provider = KeyProvider()
        key_provider.set_rsa_params(2048)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)
        self.assertIsNotNone(private_key)

        public_key = private_key.extract_public_key()
        self.assertIsNotNone(public_key)

        plain_message = "test data"

        encrypted_data = public_key.encrypt(plain_message)
        decrypted_data = private_key.decrypt(encrypted_data)

        self.assertEqual(plain_message, decrypted_data.decode())

    def test_generate_private_key_rsa_2048_and_then_do_sign_hash_and_verify_hash(self):
        key_provider = KeyProvider()
        key_provider.set_rsa_params(2048)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)
        self.assertIsNotNone(private_key)

        public_key = private_key.extract_public_key()
        self.assertIsNotNone(public_key)

        signature = private_key.sign_hash(TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST, VscfAlgId.SHA512)

        verified = public_key.verify_hash(TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST, VscfAlgId.SHA512, signature)
        self.assertTrue(verified)

    def test_generate_private_key_rsa_4096_with_key_material_rng(self):
        key_material_rng = KeyMaterialRng()
        key_material_rng.reset_key_material(TestData.DETERMINISTIC_KEY_KEY_MATERIAL)

        key_provider = KeyProvider()
        key_provider.set_random(key_material_rng)
        key_provider.set_rsa_params(4096)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)
        self.assertIsNotNone(private_key)

        exported_private_key = private_key.export_private_key()
        self.assertIsNotNone(exported_private_key)

        self.assertEqual(TestData.DETERMINISTIC_KEY_RSA4096_PRIVATE_KEY, exported_private_key)

    def test_import_public_key_ed25519_and_then_export(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        public_key = key_provider.import_public_key(TestData.ED25519_PUBLIC_KEY_PKCS8_DER)
        self.assertIsNotNone(public_key)

        exported_public_key = key_provider.export_public_key(public_key)
        self.assertIsNotNone(exported_public_key)

        self.assertEqual(TestData.ED25519_PUBLIC_KEY_PKCS8_DER, exported_public_key)

    def test_import_private_key_ed25519_and_then_export(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.import_private_key(TestData.ED25519_PRIVATE_KEY_PKCS8_DER)
        self.assertIsNotNone(private_key)

        exported_private_key = key_provider.export_private_key(private_key)
        self.assertIsNotNone(exported_private_key)

        self.assertEqual(TestData.ED25519_PRIVATE_KEY_PKCS8_DER, exported_private_key)

    def test_import_public_key_rsa2048_and_then_export(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        public_key = key_provider.import_public_key(TestData.RSA_PCKS8_2048_PUBLIC_KEY_DER)
        self.assertIsNotNone(public_key)

        exported_public_key = key_provider.export_public_key(public_key)
        self.assertIsNotNone(exported_public_key)

        self.assertEqual(TestData.RSA_PCKS8_2048_PUBLIC_KEY_DER, exported_public_key)

    def test_import_private_key_rsa2048_and_then_export(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.import_private_key(TestData.RSA_PCKS8_2048_PRIVATE_KEY_DER)
        self.assertIsNotNone(private_key)

        exported_private_key = key_provider.export_private_key(private_key)
        self.assertIsNotNone(exported_private_key)

        self.assertEqual(TestData.RSA_PCKS8_2048_PRIVATE_KEY_DER, exported_private_key)


