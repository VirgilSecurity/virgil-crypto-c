import unittest

from virgil_crypto_lib.foundation import RecipientCipher, KeyAsn1Deserializer, KeyProvider
from virgil_crypto_lib.tests.data import TestData


class RecipientCipherTest(unittest.TestCase):

    def test_encrypt_decrypt_with_ed25519_key_recipient(self):
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        key_deserializer = KeyAsn1Deserializer()
        key_deserializer.setup_defaults()
        public_key = key_provider.import_public_key(TestData.RECIPIENT_CIPHER_ED25519_PUBLIC_KEY)
        private_key = key_provider.import_private_key(TestData.RECIPIENT_CIPHER_ED25519_PRIVATE_KEY)

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
        key_provider = KeyProvider()
        key_provider.setup_defaults()

        key_deserializer = KeyAsn1Deserializer()
        key_deserializer.setup_defaults()

        private_key = key_provider.import_private_key(TestData.RECIPIENT_CIPHER_ED25519_PRIVATE_KEY)

        recipient_cipher = RecipientCipher()

        message_info = bytearray()
        recipient_cipher.start_decryption_with_key(TestData.RECIPIENT_CIPHER_ED25519_RECIPIENT_ID, private_key, message_info)

        decrypted_message = recipient_cipher.process_decryption(TestData.RECIPIENT_CIPHER_ENCRYPTED_MESSAGE)
        decrypted_message += recipient_cipher.finish_decryption()

        self.assertEqual(TestData.RECIPIENT_CIPHER_MESSAGE_2, decrypted_message)


