import os
import unittest
from virgil_crypto_lib.phe.cipher import Cipher


class CipherTest(unittest.TestCase):

    def test_encrypt_decrypt(self):
        some_text = "plain text"
        account_key = bytearray(os.urandom(32))

        self.assertEqual(len(account_key), 32)

        cipher = Cipher()
        cipher.setup_defaults()

        encrypted_data = cipher.encrypt(bytearray(some_text.encode()), account_key)
        decrypted_data = cipher.decrypt(encrypted_data, account_key)

        self.assertEqual(some_text, decrypted_data.decode())
