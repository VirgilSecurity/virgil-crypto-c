from virgil_crypto.common._c_bridge import Data, Buffer
from virgil_crypto.phe._c_bridge import VscePheCipher


class Cipher(object):

    def __init__(self):
        self._lib_vsc_phe_cipher = VscePheCipher()
        self._cipher = self._lib_vsc_phe_cipher.vsce_phe_cipher_new()

    def __delete__(self, instance):
        self._lib_vsc_phe_cipher.vsce_phe_cipher_delete(self._cipher)

    def setup_defaults(self):
        self._lib_vsc_phe_cipher.vsce_phe_cipher_setup_defaults(self._cipher)

    def encrypt(self, data, account_key):
        encrypted_buffer = Buffer(
            self._lib_vsc_phe_cipher.vsce_phe_cipher_encrypt_len(
                self._cipher,
                len(data)
            )
        )
        d_data = Data(data)
        d_account_key = Data(account_key)
        self._lib_vsc_phe_cipher.vsce_phe_cipher_encrypt(
            self._cipher,
            d_data.data,
            d_account_key.data,
            encrypted_buffer.c_buffer
        )
        return encrypted_buffer.get_bytes()

    def decrypt(self, encrypted_data, account_key):
        decrypted_buffer = Buffer(
            self._lib_vsc_phe_cipher.vsce_phe_cipher_decrypt_len(
                self._cipher,
                len(encrypted_data)
            )
        )
        d_encrypted_data = Data(encrypted_data)
        d_account_key = Data(account_key)
        self._lib_vsc_phe_cipher.vsce_phe_cipher_decrypt(
            self._cipher,
            d_encrypted_data.data,
            d_account_key.data,
            decrypted_buffer.c_buffer
        )
        return decrypted_buffer.get_bytes()
