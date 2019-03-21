from ctypes import POINTER, Structure, c_size_t

from virgil_crypto._libs import LowLevelLibs
from virgil_crypto.common._c_bridge import vsc_buffer_t, vsc_data_t
from ._vscf_impl import vscf_impl_t


class vscf_kdf1_t(Structure):
    pass


class VscfKdf1(object):

    def __init__(self):
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_kdf1_new(self):
        vscf_kdf1_new = self._lib.vscf_kdf1_new
        vscf_kdf1_new.argtypes = []
        vscf_kdf1_new.restype = POINTER(vscf_kdf1_t)
        return vscf_kdf1_new()

    def vscf_kdf1_use_hash(self, kdf, hash_):
        vscf_kdf1_use_hash = self._lib.vscf_kdf1_use_hash
        vscf_kdf1_use_hash.argtypes = [POINTER(vscf_kdf1_t), POINTER(vscf_impl_t)]
        vscf_kdf1_use_hash.restype = None
        return vscf_kdf1_use_hash(kdf, hash_)

    def vscf_kdf1_delete(self, kdf1):
        vscf_kdf1_delete = self._lib.vscf_kdf1_delete
        vscf_kdf1_delete.argtypes = [POINTER(vscf_kdf1_t)]
        vscf_kdf1_delete.restype = None
        return vscf_kdf1_delete(kdf1)

    def vscf_kdf1_derive(self, kdf1, data, key_len, key):
        vscf_kdf1_derive = self._lib.vscf_kdf1_derive
        vscf_kdf1_derive.argtypes = [POINTER(vscf_kdf1_t), vsc_data_t, c_size_t, POINTER(vsc_buffer_t)]
        vscf_kdf1_derive.restype = None
        return vscf_kdf1_derive(kdf1, data, key_len, key)