import unittest
from base64 import b64encode
from binascii import unhexlify

from virgil_crypto_lib.foundation.sha256 import Sha256
from virgil_crypto_lib.tests.data import TestData


class Sha256Test(unittest.TestCase):

    def test_sha256_hash_empty_string_success(self):
        sha_hash = Sha256().hash(bytearray("".encode()))
        self.assertEqual("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", b64encode(sha_hash).decode())

    def test_hash_empty_bytes(self):
        sha256 = Sha256()
        empty_bytes_hash = sha256.hash(TestData.SHA256_VECTOR_1_INPUT_BYTES)
        self.assertEqual(
            empty_bytes_hash,
            TestData.SHA256_VECTOR_1_DIGEST_BYTES
        )

    def test_vector_2(self):
        sha256 = Sha256()
        data_hash = sha256.hash(TestData.SHA256_VECTOR_2_INPUT_BYTES)
        self.assertEqual(
            data_hash,
            TestData.SHA256_VECTOR_2_DIGEST_BYTES
        )

    def test_vector_3(self):
        sha256 = Sha256()
        data_hash = sha256.hash(TestData.SHA256_VECTOR_3_INPUT_BYTES)
        self.assertEqual(
            data_hash,
            TestData.SHA256_VECTOR_3_DIGEST_BYTES
        )

    # Test implementation for hash stream

    def test_hash_stream_vector_1(self):
        sha256 = Sha256()

        sha256.start()
        sha256.update(TestData.SHA256_VECTOR_1_INPUT_BYTES)
        digest = sha256.finish()

        self.assertEqual(len(TestData.SHA256_VECTOR_1_DIGEST_BYTES), len(digest))
        self.assertEqual(TestData.SHA256_VECTOR_1_DIGEST_BYTES, digest)

    def test_hash_stream_vector_2(self):
        sha256 = Sha256()
        sha256.start()
        sha256.update(TestData.SHA256_VECTOR_2_INPUT_BYTES)
        digest = sha256.finish()

        self.assertEqual(len(TestData.SHA256_VECTOR_2_DIGEST_BYTES), len(digest))
        self.assertEqual(TestData.SHA256_VECTOR_2_DIGEST_BYTES, digest)

    def test_hash_stream_vector_3(self):
        sha256 = Sha256()

        sha256.start()
        sha256.update(TestData.SHA256_VECTOR_3_INPUT_BYTES)
        digest = sha256.finish()

        self.assertEqual(len(TestData.SHA256_VECTOR_3_DIGEST_BYTES), len(digest))
        self.assertEqual(TestData.SHA256_VECTOR_3_DIGEST_BYTES, digest)