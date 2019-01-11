from ctypes import c_size_t, c_byte

from .phe import Phe


class Data(object):

    def __init__(self, data):
        # type: (bytearray) -> None
        self.__phe = Phe()
        self.data_bytes = (c_byte * len(data))(*data)
        self.data = self.__phe.vsc_data(
            self.data_bytes,
            c_size_t(len(data))
        )
