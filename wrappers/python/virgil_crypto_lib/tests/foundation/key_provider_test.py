import unittest

from virgil_crypto_lib.foundation import KeyProvider, KeyMaterialRng, Ed25519, Rsa
from virgil_crypto_lib.foundation._c_bridge import VscfAlgId, VirgilCryptoFoundationError
from virgil_crypto_lib.tests.data import TestData


class KeyProviderTest(unittest.TestCase):

    def test_generate_private_key_ed25519(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)

        self.assertIsNotNone(private_key)

        self.assertEqual(VscfAlgId.ED25519, private_key.alg_id())
        self.assertEqual(32, len(private_key))

    def test_generate_private_key_ed25519_and_then_do_encrypt_decrypt(self):
        ed25519_alg = Ed25519()
        ed25519_alg.setup_defaults()

        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)

        public_key = private_key.extract_public_key()

        plain_message = "test data"
        encrypted_data = ed25519_alg.encrypt(public_key, plain_message)

        decrypted_data = ed25519_alg.decrypt(private_key, encrypted_data)

        self.assertEqual(plain_message, decrypted_data.decode())

    def test_generate_private_key_ed25519_and_then_do_sign_hash_and_verify_hash(self):
        ed25519_alg = Ed25519()
        ed25519_alg.setup_defaults()

        key_provider = KeyProvider()
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)
        public_key = private_key.extract_public_key()

        signature = ed25519_alg.sign_hash(private_key, VscfAlgId.SHA512, TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST)

        verified = ed25519_alg.verify_hash(public_key, VscfAlgId.SHA512, TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST,  signature)
        self.assertTrue(verified)

    def test_generate_private_key_ed25519_with_key_material_rng(self):
        ed25519_alg = Ed25519()
        ed25519_alg.setup_defaults()

        key_material_rng = KeyMaterialRng()
        key_material_rng.reset_key_material(TestData.DETERMINISTIC_KEY_KEY_MATERIAL)

        key_provider = KeyProvider()
        key_provider.set_random(key_material_rng)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.ED25519)
        self.assertIsNotNone(private_key)

        exported_private_key = ed25519_alg.export_private_key(private_key)

        self.assertIsNotNone(exported_private_key)
        self.assertEqual(TestData.DETERMINISTIC_KEY_ED25519_PRIVATE_KEY, exported_private_key.data())

    def test_generate_private_key_rsa_2048(self):
        key_provider = KeyProvider()
        key_provider.set_rsa_params(2048)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)

        self.assertIsNotNone(private_key)
        self.assertEqual(VscfAlgId.RSA, private_key.alg_id())
        self.assertEqual(2048, private_key.bitlen())

    def test_generate_private_key_rsa_2048_and_then_do_encrypt_decrypt(self):
        rsa_alg = Rsa()
        rsa_alg.setup_defaults()

        key_provider = KeyProvider()
        key_provider.set_rsa_params(2048)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)
        self.assertIsNotNone(private_key)

        public_key = private_key.extract_public_key()
        self.assertIsNotNone(public_key)

        plain_message = "test data"

        encrypted_data = rsa_alg.encrypt(public_key, plain_message)
        decrypted_data = rsa_alg.decrypt(private_key, encrypted_data)

        self.assertEqual(plain_message, decrypted_data.decode())

    def test_generate_private_key_rsa_2048_and_then_do_sign_hash_and_verify_hash(self):
        rsa_alg = Rsa()
        rsa_alg.setup_defaults()

        key_provider = KeyProvider()
        key_provider.set_rsa_params(2048)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)
        self.assertIsNotNone(private_key)

        public_key = private_key.extract_public_key()
        self.assertIsNotNone(public_key)

        signature = rsa_alg.sign_hash(private_key, VscfAlgId.SHA512, TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST)

        verified = rsa_alg.verify_hash(public_key, VscfAlgId.SHA512, TestData.KEY_PROVIDER_MESSAGE_SHA512_DIGEST, signature)
        self.assertTrue(verified)

    def test_generate_private_key_rsa_4096_with_key_material_rng(self):
        rsa_alg = Rsa()
        rsa_alg.setup_defaults()

        key_material_rng = KeyMaterialRng()
        key_material_rng.reset_key_material(TestData.DETERMINISTIC_KEY_KEY_MATERIAL)

        key_provider = KeyProvider()
        key_provider.set_random(key_material_rng)
        key_provider.set_rsa_params(4096)
        key_provider.setup_defaults()

        private_key = key_provider.generate_private_key(VscfAlgId.RSA)
        self.assertIsNotNone(private_key)

        exported_private_key = rsa_alg.export_private_key(private_key)
        self.assertIsNotNone(exported_private_key)

        self.assertEqual(TestData.DETERMINISTIC_KEY_RSA4096_PRIVATE_KEY, exported_private_key.data())

    def test_import_public_key_ed25519_and_then_export(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        public_key = key_provider.import_public_key(TestData.ED25519_PUBLIC_KEY_PKCS8_DER)
        self.assertIsNotNone(public_key)

        exported_public_key = key_provider.export_public_key(public_key)
        self.assertIsNotNone(exported_public_key)

        self.assertEqual(TestData.ED25519_PUBLIC_KEY_PKCS8_DER, exported_public_key)

    def test_import_public_key_ed25519_from_corrupted_data(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        test_data = bytearray("Lorem Ipsum is simply dummy text of the printing and typesetting industry.".encode())
        self.assertRaises(VirgilCryptoFoundationError, key_provider.import_public_key, test_data)

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


