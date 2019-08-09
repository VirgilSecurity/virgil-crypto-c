from virgil_crypto._libs import LowLevelLibs
from ctypes import Structure, POINTER, c_int, c_size_t

from virgil_crypto.common._c_bridge import vsc_data_t, vsc_buffer_t


class vsce_phe_cipher_t(Structure):
    pass


class VscePheCipher(object):

    def __init__(self):
        self._ll = LowLevelLibs()
        self._lib_common = self._ll.common
        self._lib_foundation = self._ll.foundation
        self._lib = self._ll.phe

    def vsce_phe_cipher_new(self):
        vsce_phe_cipher_new = self._lib.vsce_phe_cipher_new
        vsce_phe_cipher_new.argtypes = []
        vsce_phe_cipher_new.restype = POINTER(vsce_phe_cipher_t)
        return vsce_phe_cipher_new()

    def vsce_phe_cipher_setup_defaults(self, cipher):
        vsce_phe_cipher_setup_defaults = self._lib.vsce_phe_cipher_setup_defaults
        vsce_phe_cipher_setup_defaults.argtypes = [POINTER(vsce_phe_cipher_t)]
        vsce_phe_cipher_setup_defaults.restype = None
        return vsce_phe_cipher_setup_defaults(cipher)

    def vsce_phe_cipher_delete(self, phe_cipher):
        vsce_phe_cipher_delete = self._lib.vsce_phe_cipher_delete
        vsce_phe_cipher_delete.argtypes = [POINTER(vsce_phe_cipher_t)]
        vsce_phe_cipher_delete.restype = None
        return vsce_phe_cipher_delete(phe_cipher)

    def vsce_phe_cipher_encrypt_len(self, cipher, data_len):
        vsce_phe_cipher_encrypt_len = self._lib.vsce_phe_cipher_encrypt_len
        vsce_phe_cipher_encrypt_len.argtypes = [POINTER(vsce_phe_cipher_t), c_size_t]
        vsce_phe_cipher_encrypt_len.restype = c_size_t
        return vsce_phe_cipher_encrypt_len(cipher, data_len)

    def vsce_phe_cipher_encrypt(self, phe_cipher, data, account_key, encrypted_data):
        vsce_phe_cipher_encrypt = self._lib.vsce_phe_cipher_encrypt
        vsce_phe_cipher_encrypt.argtypes = [POINTER(vsce_phe_cipher_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_cipher_encrypt.restype = c_int
        return vsce_phe_cipher_encrypt(phe_cipher, data, account_key, encrypted_data)

    def vsce_phe_cipher_decrypt_len(self, cipher, encrypted_data_len):
        vsce_phe_cipher_decrypt_len = self._lib.vsce_phe_cipher_decrypt_len
        vsce_phe_cipher_decrypt_len.argtypes = [POINTER(vsce_phe_cipher_t), c_size_t]
        vsce_phe_cipher_decrypt_len.restype = c_size_t
        return vsce_phe_cipher_decrypt_len(cipher, encrypted_data_len)

    def vsce_phe_cipher_decrypt(self, phe_cipher, encrypted_data, account_key, data):
        vsce_phe_cipher_decrypt = self._lib.vsce_phe_cipher_decrypt
        vsce_phe_cipher_decrypt.argtypes = [POINTER(vsce_phe_cipher_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_cipher_decrypt.restype = c_int
        return vsce_phe_cipher_decrypt(phe_cipher, encrypted_data, account_key, data)
