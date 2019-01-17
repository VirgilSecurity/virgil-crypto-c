from ctypes import Structure, POINTER, c_size_t, c_byte, c_bool, c_char_p

from virgil_crypto._libs.low_level_libs import LowLevelLibs


# C structure wrapper
class vsc_data_t(Structure):
    _fields_ = [
        ("bytes", POINTER(c_byte)),
        ("len", c_size_t)
    ]


class VscData(object):

    def __init__(self):
        self._lib = LowLevelLibs().common

    def vsc_data(self, bytes_, len_):
        vsc_data = self._lib.vsc_data
        vsc_data.argtypes = [POINTER(c_byte), c_size_t]
        vsc_data.restype = vsc_data_t
        return vsc_data(bytes_, len_)

    def vsc_data_from_str(self, str_):
        vsc_data_from_str = self._lib.vsc_data_from_str
        vsc_data_from_str.argtypes = [c_char_p, c_size_t]
        vsc_data_from_str.restype = vsc_data_t
        return vsc_data_from_str(str_)

    def vsc_data_empty(self):
        vsc_data_empty = self._lib.vsc_data_empty
        vsc_data_empty.restype = vsc_data_t
        return vsc_data_empty()

    def vsc_data_is_valid(self, data):
        # type: (vsc_data_t)->bool
        vsc_data_is_valid = self._lib.vsc_data_is_valid
        vsc_data_is_valid.argtypes = [vsc_data_t]
        vsc_data_is_valid.restype = c_bool
        return vsc_data_is_valid(data)

    def vsc_data_is_zero(self, data):
        vsc_data_is_zero = self._lib.vsc_data_is_zero
        vsc_data_is_zero.argtypes = [vsc_data_t]
        vsc_data_is_zero.restype = c_bool
        return vsc_data_is_zero(data)

    def vsc_data_is_empty(self, data):
        # type:
        vsc_data_is_empty = self._lib.vsc_data_is_empty
        vsc_data_is_empty.argtypes = [vsc_data_t]
        vsc_data_is_empty.restype = c_bool
        return vsc_data_is_empty(data)

    def vsc_data_equal(self, data, rhs):
        # type: (vsc_data_t, vsc_data_t)->bool
        vsc_data_equal = self._lib.vsc_data_equal
        vsc_data_equal.argtypes = [vsc_data_t, vsc_data_t]
        vsc_data_equal.restype = c_bool
        return vsc_data_equal(data, rhs)

    def vsc_data_slice_beg(self, data, offset, len_):
        vsc_data_slice_beg = self._lib.vsc_data_slice_beg
        vsc_data_slice_beg.argtypes = [vsc_data_t, c_size_t, c_size_t]
        vsc_data_slice_beg.restype = vsc_data_t
        return vsc_data_slice_beg(data, offset, len_)

    def vsc_data_slice_end(self, data, offset, len_):
        vsc_data_slice_end = self._lib.vsc_data_slice_end
        vsc_data_slice_end.argtypes = [vsc_data_t, c_size_t, c_size_t]
        vsc_data_slice_end.restype = vsc_data_t
        return vsc_data_slice_end(data, offset, len_)
