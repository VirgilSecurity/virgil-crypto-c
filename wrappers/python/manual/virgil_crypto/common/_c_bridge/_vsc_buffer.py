from ctypes import Structure, POINTER, c_size_t, c_byte, c_bool, c_char_p
from ._vsc_data import vsc_data_t

from virgil_crypto._libs import LowLevelLibs


# C structure wrapper
class vsc_buffer_t(Structure):
    pass


class VscBuffer(object):

    def __init__(self):
        self._lib = LowLevelLibs().phe

    def vsc_buffer_new(self):
        # vsc_buffer_new C function wrapper
        vsc_buffer_new = self._lib.vsc_buffer_new
        vsc_buffer_new.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_new()

    def vsc_buffer_new_with_data(self, data):
        # vsc_buffer_new_with_data C function wrapper
        vsc_buffer_new_with_data = self._lib.vsc_buffer_new_with_data
        vsc_buffer_new_with_data.argtypes = [vsc_data_t]
        vsc_buffer_new_with_data.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_new_with_data(data)

    def vsc_buffer_destroy(self, buffer):
        # vsc_buffer_destroy C function wrapper
        vsc_buffer_destroy = self._lib.vsc_buffer_destroy
        vsc_buffer_destroy.argtypes = [POINTER(POINTER(vsc_buffer_t))]
        return vsc_buffer_destroy(buffer)

    def vsc_buffer_is_empty(self, buffer):
        vsc_buffer_is_empty = self._lib.vsc_buffer_is_empty
        vsc_buffer_is_empty.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_is_empty.restype = c_bool
        return vsc_buffer_is_empty(buffer)

    def vsc_buffer_equal(self, buffer, rhs):
        vsc_buffer_equal = self._lib.vsc_buffer_equal
        vsc_buffer_equal.argtypes = [POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsc_buffer_equal.restype = c_bool
        return vsc_buffer_equal(buffer, rhs)

    def vsc_buffer_alloc(self, buffer, capacity):
        vsc_buffer_alloc = self._lib.vsc_buffer_alloc
        vsc_buffer_alloc.argtypes = [POINTER(vsc_buffer_t), c_size_t]
        vsc_buffer_alloc.restype = None
        return vsc_buffer_alloc(buffer, capacity)

    def vsc_buffer_use(self, buffer, bytes_, bytes_len):
        # vsc_buffer_use C function wrapper
        vsc_buffer_use = self._lib.vsc_buffer_use
        vsc_buffer_use.argtypes = [
            POINTER(vsc_buffer_t),
            POINTER(c_byte),
            c_size_t
        ]
        return vsc_buffer_use(buffer, bytes_, bytes_len)

    def vsc_buffer_make_secure(self, buffer):
        vsc_buffer_make_secure = self._lib.vsc_buffer_make_secure
        vsc_buffer_make_secure.argtypes = [POINTER(vsc_buffer_make_secure)]
        vsc_buffer_make_secure.restype = None
        return vsc_buffer_make_secure(buffer)

    def vsc_buffer_is_full(self, buffer):
        vsc_buffer_is_full = self._lib.vsc_buffer_is_full
        vsc_buffer_is_full.argtypes = [POINTER(vsc_buffer_is_full)]
        vsc_buffer_is_full.restype = c_bool
        return vsc_buffer_is_full(buffer)

    def vsc_buffer_is_valid(self, buffer):
        vsc_buffer_is_valid = self._lib.vsc_buffer_is_valid
        vsc_buffer_is_valid.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_is_valid.restype = c_bool
        return vsc_buffer_is_valid(buffer)

    def vsc_buffer_bytes(self, buffer):
        vsc_buffer_bytes = self._lib.vsc_buffer_bytes
        vsc_buffer_bytes.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_bytes.restype = POINTER(c_byte)
        return vsc_buffer_bytes(buffer)

    def vsc_buffer_data(self, buffer):
        vsc_buffer_data = self._lib.vsc_buffer_data
        vsc_buffer_data.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_data.restype = vsc_data_t
        return vsc_buffer_data(buffer)

    def vsc_buffer_capacity(self, buffer):
        vsc_buffer_capacity = self._lib.vsc_buffer_capacity
        vsc_buffer_capacity.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_capacity.restype = c_size_t
        return vsc_buffer_capacity(buffer)

    def vsc_buffer_len(self, buffer):
        vsc_buffer_len = self._lib.vsc_buffer_len
        vsc_buffer_len.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_len.restype = c_size_t
        return vsc_buffer_len(buffer)

    def vsc_buffer_begin(self, buffer):
        vsc_buffer_begin = self._lib.vsc_buffer_begin
        vsc_buffer_begin.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_begin.restype = POINTER(c_byte)
        return vsc_buffer_begin(buffer)

    def vsc_buffer_inc_used(self, buffer, len_):
        vsc_buffer_inc_used = self._lib.vsc_buffer_inc_used
        vsc_buffer_inc_used.argtypes = [POINTER(vsc_buffer_t), c_size_t]
        vsc_buffer_inc_used.restype = None
        return vsc_buffer_inc_used(buffer, len_)

    def vsc_buffer_dec_used(self, buffer, len_):
        vsc_buffer_dec_used = self._lib.vsc_buffer_dec_used
        vsc_buffer_dec_used.argtypes = [POINTER(vsc_buffer_t), c_size_t]
        vsc_buffer_dec_used.restype = None
        return vsc_buffer_dec_used(buffer, len_)

    def vsc_buffer_write_data(self, buffer, data):
        vsc_buffer_write_data = self._lib.vsc_buffer_write_data
        vsc_buffer_write_data.argtypes = [POINTER(vsc_buffer_t), vsc_data_t]
        vsc_buffer_write_data.restype = None
        return vsc_buffer_write_data(buffer, data)

    def vsc_buffer_reset(self, buffer):
        vsc_buffer_reset = self._lib.vsc_buffer_reset
        vsc_buffer_reset.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_reset.restype = None
        return vsc_buffer_reset(buffer)

    def vsc_buffer_erase(self, buffer):
        vsc_buffer_erase = self._lib.vsc_buffer_erase
        vsc_buffer_erase.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_erase.restype = None
        return vsc_buffer_erase(buffer)

