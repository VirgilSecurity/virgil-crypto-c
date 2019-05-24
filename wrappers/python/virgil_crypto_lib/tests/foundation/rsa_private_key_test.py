import unittest
from binascii import unhexlify
from ctypes import cast, POINTER, c_byte

from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.foundation import RsaPrivateKey, FakeRandom, KeyMaterialRng
from virgil_crypto_lib.foundation._c_bridge import *
from virgil_crypto_lib.tests.data.test_data import TestData
from virgil_crypto_lib.utils import Utils


class RsaPrivateKeyTest(unittest.TestCase):

    def test_rsa_private_key_len_imported_2048_private_key_pkcs1_returns_256(self):
        private_key = RsaPrivateKey()
        private_key.setup_defaults()
        private_key.import_private_key(TestData.RSA_PKCS1_2048_PRIVATE_KEY)
        self.assertEqual(256, private_key.key_len())

    def test_rsa_private_key_from_imported_2048_private_key_pkcs1_equal(self):
        private_key = RsaPrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.RSA_PKCS1_2048_PRIVATE_KEY)

        exported_key = private_key.export_private_key()

        self.assertEqual(len(TestData.RSA_PKCS1_2048_PRIVATE_KEY), len(exported_key))
        self.assertEqual(TestData.RSA_PKCS1_2048_PRIVATE_KEY, exported_key)

    def test_rsa_private_key_decrypt_imported_2048_private_key_pcks1_and_2048_encrypted_data_and_random_ab_and_hash_sha512(self):
        private_key = RsaPrivateKey()

        fake_random = FakeRandom()
        fake_random.setup_source_byte(Utils.convert_byte_to_c_byte(unhexlify("AB")))

        private_key.set_random(fake_random)
        private_key.setup_defaults()

        private_key.import_private_key(TestData.RSA_PKCS1_2048_PRIVATE_KEY)

        decrypted_data = private_key.decrypt(TestData.RSA_ENCRYPTED_DATA_1)

        self.assertEqual(len(TestData.RSA_DATA_1), len(decrypted_data))
        self.assertEqual(TestData.RSA_DATA_1, decrypted_data)


    def test_rsa_private_key_extract_public_key_from_imported_2048_private_key_pkcs1_when_exported_equals_2048_public_key_pkcs1(self):
        private_key = RsaPrivateKey()
        private_key.setup_defaults()

        private_key.import_private_key(TestData.RSA_PKCS1_2048_PRIVATE_KEY)

        public_key = private_key.extract_public_key()
        exported_public_key = public_key.export_public_key()

        self.assertEqual(len(TestData.RSA_PKCS1_2048_PUBLIC_KEY), len(exported_public_key))
        self.assertEqual(TestData.RSA_PKCS1_2048_PUBLIC_KEY, exported_public_key)

    def test_rsa_private_key_sign_hash_imported_2048_private_key_pkcs1_and_random_AB_and_hash_sha512_and_DATA_1(self):
        private_key = RsaPrivateKey()

        fake_random = FakeRandom()
        fake_random.setup_source_byte(Utils.convert_byte_to_c_byte(unhexlify("AB")))
        private_key.set_random(fake_random)
        private_key.setup_defaults()

        private_key.import_private_key(TestData.RSA_PKCS1_2048_PRIVATE_KEY)

        signature = private_key.sign_hash(TestData.RSA_DATA_1_SHA512_DIGEST, VscfAlgId.SHA512)

        self.assertEqual(TestData.RSA_DATA_1_SHA512_SIGNATURE, signature)

    def test_rsa_private_key_generate_key_bitlen_2048_and_exponent_3(self):
        private_key = RsaPrivateKey()

        key_material_rng = KeyMaterialRng()

        key_material_rng.reset_key_material(TestData.RSA_DETERMINISTIC_KEY_MATERIAL)

        private_key.set_random(key_material_rng)
        private_key.set_keygen_params(2048)
        private_key.setup_defaults()

        private_key.generate_key()

        exported_key = private_key.export_private_key()

        self.assertEqual(TestData.RSA_GENERATED_PRIVATE_KEY_PKCS1_2048, exported_key)
