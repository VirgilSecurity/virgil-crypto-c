import unittest
from binascii import unhexlify

from virgil_crypto_lib.foundation.kdf1 import Kdf1
from virgil_crypto_lib.foundation.sha256 import Sha256


class Kdf1Test(unittest.TestCase):

    def test_derive_key_from_empty_bytes(self):
        kdf1 = Kdf1()
        kdf1.set_hash(Sha256())
        vector_1_data = bytearray([])
        vector_1_key = "DF3F619804A92FDB4057192DC43DD748EA778ADC52BC498CE80524C014B81119B40711A88C703975"
        vector_1_key_bytes = unhexlify(vector_1_key)
        key = kdf1.derive(vector_1_data, len(vector_1_key_bytes))
        self.assertEqual(len(vector_1_key_bytes), len(key))
        self.assertEqual(vector_1_key_bytes, key)

    def test_derive_vector_2(self):
        kdf1 = Kdf1()
        kdf1.set_hash(Sha256())
        vector_2_data = unhexlify("BD")
        vector_2_key = "A759B860B37FE77847406F266B7D7F1E838D814ADDF2716ECF4D824DC8B56F71823BFAE3B6E7CD29"
        vector_2_key_bytes = unhexlify(vector_2_key)
        key = kdf1.derive(vector_2_data, len(vector_2_key_bytes))
        self.assertEqual(len(vector_2_key_bytes), len(key))
        self.assertEqual(vector_2_key_bytes, key)

    def test_derive_vector_3(self):
        kdf1 = Kdf1()
        kdf1.set_hash(Sha256())
        vector_3_data = unhexlify("5FD4")
        vector_3_key = "C6067722EE5661131D53437E649ED1220858F88164819BB867D6478714F8F3C8002422AFDD96BF48"
        vector_3_key_bytes = unhexlify(vector_3_key)
        key = kdf1.derive(vector_3_data, len(vector_3_key_bytes))
        self.assertEqual(len(vector_3_key_bytes), len(key))
        self.assertEqual(vector_3_key_bytes, key)
