from ctypes import c_size_t, c_byte

from .data import Data
from .phe import Phe


class Buffer(object):

    def __init__(self, size, data=None):
        self.__phe = Phe()
        if data:
            self.buffer_bytes = (c_byte * size)(*data)
            self.c_buffer = self.__phe.vsc_buffer_new_with_data(Data(self.buffer_bytes).data)
        else:
            self.buffer_bytes = (c_byte * size)()
            self.c_buffer = self.__phe.vsc_buffer_new()
            self.__phe.vsc_buffer_use(
                self.c_buffer,
                self.buffer_bytes,
                c_size_t(size)
            )

    def __delete__(self, instance):
        self.destroy()

    def get_data(self):
        return bytearray(self.buffer_bytes)

    def destroy(self):
        self.__phe.vsc_buffer_destroy(self.c_buffer)
