from virgil_crypto.common._c_bridge import VscBuffer
from ctypes import c_byte, c_size_t
from ._data import Data


class Buffer(object):

    def __init__(self, capacity, data=None):
        self._lib_vsc_buffer = VscBuffer()
        if data:
            self._capacity = capacity
            self._bytes_ = (c_byte * capacity)(*data)
            self.c_buffer = self._lib_vsc_buffer.vsc_buffer_new_with_data(Data(self._bytes_).data)
        else:
            self._bytes_ = (c_byte * capacity)()
            self.c_buffer = self._lib_vsc_buffer.vsc_buffer_new()
            self._lib_vsc_buffer.vsc_buffer_use(
                self.c_buffer,
                self._bytes_,
                c_size_t(capacity)
            )

    def __len__(self):
        return len(self._bytes_)

    def __eq__(self, other):
        return self._lib_vsc_buffer.vsc_buffer_equal(self.c_buffer, other.c_buffer)

    def __bytes__(self):
        return self.get_bytes()

    def __delete__(self, instance):
        self._lib_vsc_buffer.vsc_buffer_destroy(self.c_buffer)

    def is_empty(self):
        return self._lib_vsc_buffer.vsc_buffer_is_empty(self.c_buffer)

    def alloc(self, capacity):
        self._lib_vsc_buffer.vsc_buffer_alloc(self.c_buffer, capacity)

    def use(self, bytes_, bytes_len):
        self._lib_vsc_buffer.vsc_buffer_use(self.c_buffer, bytes_, bytes_len)

    def take(self):
        pass

    def make_secure(self):
        pass

    def is_full(self):
        pass

    def if_valid(self):
        pass

    def get_bytes(self):
        return bytearray(self._bytes_)

    def get_data(self):
        return self._lib_vsc_buffer.vsc_buffer_data(self.c_buffer)

    def get_capacity(self):
        pass

    def get_len(self):
        pass

    def begin(self):
        pass

    def inc_used(self):
        pass

    def dec_used(self):
        pass

    def write_str(self):
        pass

    def write_data(self):
        pass

    def reset(self):
        pass

    def erase(self):
        pass

    @property
    def capacity(self):
        return self._capacity
