import unittest

from virgil_crypto.common._c_bridge import Data
from virgil_crypto.foundation import Pkcs8DerSerializer, Pkcs8DerDeserializer, AlgFactory, RecipientCipher
from virgil_crypto.tests.data import TestData


class RecipientCipherTest(unittest.TestCase):

    def test_encrypt_decrypt_with_ed25519_key_recipient(self):
        pkcs8 = Pkcs8DerDeserializer()
        pkcs8.setup_defaults()

        raw_public_key = pkcs8.deserialize_public_key(TestData.RECIPIENT_CIPHER_ED25519_PUBLIC_KEY)
        public_key = AlgFactory().create_public_key_from_raw_key(raw_public_key)

        raw_private_key = pkcs8.deserialize_private_key(TestData.RECIPIENT_CIPHER_ED25519_PRIVATE_KEY)
        private_key = AlgFactory().create_private_key_from_raw_key(raw_private_key)

        recipient_cipher = RecipientCipher()

        recipient_cipher.add_key_recipient(TestData.RECIPIENT_CIPHER_ED25519_RECIPIENT_ID, public_key)

        recipient_cipher.start_encryption()

        encrypted_message = recipient_cipher.pack_message_info()
        encrypted_message += recipient_cipher.process_encryption(TestData.RECIPIENT_CIPHER_MESSAGE)
        encrypted_message += recipient_cipher.finish_encryption()

        message_info = bytearray()
        recipient_cipher.start_decryption_with_key(TestData.RECIPIENT_CIPHER_ED25519_RECIPIENT_ID, private_key, message_info)
        decrypted_message = recipient_cipher.process_decryption(encrypted_message)
        decrypted_message += recipient_cipher.finish_decryption()

        self.assertEqual(TestData.RECIPIENT_CIPHER_MESSAGE, decrypted_message)

    def test_decrypt_with_ed25519_public_key(self):
        pkcs8 = Pkcs8DerDeserializer()
        pkcs8.setup_defaults()

        raw_private_key = pkcs8.deserialize_private_key(TestData.RECIPIENT_CIPHER_ED25519_PRIVATE_KEY)
        private_key = AlgFactory().create_private_key_from_raw_key(raw_private_key)

        recipient_cipher = RecipientCipher()

        message_info = bytearray()
        recipient_cipher.start_decryption_with_key(TestData.RECIPIENT_CIPHER_ED25519_RECIPIENT_ID, private_key, message_info)

        decrypted_message = recipient_cipher.process_decryption(TestData.RECIPIENT_CIPHER_ENCRYPTED_MESSAGE)
        decrypted_message += recipient_cipher.finish_decryption()

        self.assertEqual(TestData.RECIPIENT_CIPHER_MESSAGE_2, decrypted_message)


