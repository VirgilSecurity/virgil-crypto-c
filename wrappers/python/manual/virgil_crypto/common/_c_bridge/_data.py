from ctypes import c_byte

from virgil_crypto.utils.utils import Utils
from ._vsc_data import VscData


class Data(object):

    def __init__(self, predefined_value=None):
        self._lib_vsc_data = VscData()
        if predefined_value is None:
            self._bytes_ = (c_byte * 0)()
        if isinstance(predefined_value, bytes) or isinstance(predefined_value, bytearray):
            self._bytes_ = (c_byte * len(predefined_value))(*predefined_value)
        elif isinstance(predefined_value, str) or Utils.check_unicode(predefined_value):
            str_bytes = bytearray(Utils.strtobytes(predefined_value))
            self._bytes_ = (c_byte * len(str_bytes))(*str_bytes)
        else:
            raise TypeError("Wrong type for instantiate Data")
        self.data = self._lib_vsc_data.vsc_data(self._bytes_, len(self._bytes_))

    def __eq__(self, other):
        return self._lib_vsc_data.vsc_data_equal(self.data, other.data)

    def __len__(self):
        return len(self._bytes_)

    def __bytes__(self):
        return bytearray(self._bytes_)

    def is_valid(self):
        return self._lib_vsc_data.vsc_data_is_valid(self.data)

    def is_zero(self):
        return self._lib_vsc_data.vsc_data_is_zero(self.data)

    def is_empty(self):
        return self._lib_vsc_data.vsc_data_is_empty(self.data)

    def slice_from_begining(self, offset, len_):
        return self._lib_vsc_data.vsc_data_slice_beg(self.data, offset, len_)

    def slice_from_end(self, offset, len_):
        return self._lib_vsc_data.vsc_data_slice_end(self.data, offset, len_)
