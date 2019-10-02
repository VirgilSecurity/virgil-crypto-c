from enum import IntEnum
from ctypes import Structure, POINTER

from virgil_crypto._libs import LowLevelLibs
from virgil_crypto.common._c_bridge import vsc_buffer_t, vsc_data_t
from ._vscf_impl import vscf_impl_t


class vscf_sha256_t(Structure):
    pass


class VscfSha256Constants(IntEnum):
    #
    # Length of the digest(hashing output) in bytes.
    #
    DIGEST_LEN = 32,
    #
    # Block length of the digest function in bytes.
    #
    BLOCK_LEN = 64


class VscfSha256(object):

    def __init__(self):
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_sha256_new(self):
        vscf_sha256_new = self._lib.vscf_sha256_new
        vscf_sha256_new.argtypes = []
        vscf_sha256_new.restype = POINTER(vscf_sha256_t)
        return vscf_sha256_new()

    def vscf_sha256_delete(self, sha256):
        vscf_sha256_delete = self._lib.vscf_sha256_delete
        vscf_sha256_delete.argtypes = [POINTER(vscf_sha256_t)]
        vscf_sha256_delete.restype = None
        return vscf_sha256_delete(sha256)

    def vscf_sha256_impl(self, sha256):
        vscf_sha256_impl = self._lib.vscf_sha256_impl
        vscf_sha256_impl.argtypes = [POINTER(vscf_sha256_t)]
        vscf_sha256_impl.restype = POINTER(vscf_impl_t)
        return vscf_sha256_impl(sha256)

    def vscf_sha256_hash(self, data, digest):
        vscf_sha256_hash = self._lib.vscf_sha256_hash
        vscf_sha256_hash.argtypes = [vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_sha256_hash.restype = None
        return vscf_sha256_hash(data, digest)

    def vscf_sha256_start(self, sha256):
        vscf_sha256_start = self._lib.vscf_sha256_start
        vscf_sha256_start.argtypes = [POINTER(vscf_sha256_t)]
        vscf_sha256_start.restype = None
        return vscf_sha256_start(sha256)

    def vscf_sha256_update(self, sha256, data):
        vscf_sha256_update = self._lib.vscf_sha256_update
        vscf_sha256_update.argtypes = [POINTER(vscf_sha256_t), vsc_data_t]
        vscf_sha256_update.restype = None
        return vscf_sha256_update(sha256, data)

    def vscf_sha256_finish(self, sha256, digest):
        vscf_sha256_finish = self._lib.vscf_sha256_finish
        vscf_sha256_finish.argtypes = [POINTER(vscf_sha256_t), POINTER(vsc_buffer_t)]
        vscf_sha256_finish.restype = None
        return vscf_sha256_finish(sha256, digest)
