import unittest
from base64 import b64encode
from binascii import unhexlify

from virgil_crypto.foundation.sha256 import SHA256


class Sha256Test(unittest.TestCase):

    VECTOR_1_INPUT_BYTES = bytearray()
    VECTOR_1_DIGEST_BYTES = unhexlify("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")

    VECTOR_2_INPUT_BYTES = unhexlify("BD")
    VECTOR_2_DIGEST_BYTES = unhexlify("68325720AABD7C82F30F554B313D0570C95ACCBB7DC4B5AAE11204C08FFE732B")

    VECTOR_3_INPUT_BYTES = unhexlify("5FD4")
    VECTOR_3_DIGEST_BYTES = unhexlify("7C4FBF484498D21B487B9D61DE8914B2EADAF2698712936D47C3ADA2558F6788")

    def test_sha256_hash_empty_string_success(self):
        sha_hash = SHA256().hash(bytearray("".encode()))
        self.assertEqual("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", b64encode(sha_hash).decode())

    def test_hash_empty_bytes(self):
        sha256 = SHA256()
        empty_bytes_hash = sha256.hash(self.VECTOR_1_INPUT_BYTES)
        self.assertEqual(
            empty_bytes_hash,
            self.VECTOR_1_DIGEST_BYTES
        )

    def test_vector_2(self):
        sha256 = SHA256()
        data_hash = sha256.hash(self.VECTOR_2_INPUT_BYTES)
        self.assertEqual(
            data_hash,
            self.VECTOR_2_DIGEST_BYTES
        )

    def test_vector_3(self):
        sha256 = SHA256()
        data_hash = sha256.hash(self.VECTOR_3_INPUT_BYTES)
        self.assertEqual(
            data_hash,
            self.VECTOR_3_DIGEST_BYTES
        )

    # Test implementation for hash stream

    def test_hash_stream_vector_1(self):
        sha256 = SHA256()

        sha256.start()
        sha256.update(self.VECTOR_1_INPUT_BYTES)
        digest = sha256.finish()

        self.assertEqual(len(self.VECTOR_1_DIGEST_BYTES), len(digest))
        self.assertEqual(self.VECTOR_1_DIGEST_BYTES, digest)

    def test_hash_stream_vector_2(self):
        sha256 = SHA256()
        sha256.start()
        sha256.update(self.VECTOR_2_INPUT_BYTES)
        digest = sha256.finish()

        self.assertEqual(len(self.VECTOR_2_DIGEST_BYTES), len(digest))
        self.assertEqual(self.VECTOR_2_DIGEST_BYTES, digest)

    def test_hash_stream_vector_3(self):
        sha256 = SHA256()

        sha256.start()
        sha256.update(self.VECTOR_3_INPUT_BYTES)
        digest = sha256.finish()

        self.assertEqual(len(self.VECTOR_3_DIGEST_BYTES), len(digest))
        self.assertEqual(self.VECTOR_3_DIGEST_BYTES, digest)