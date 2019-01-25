import os
from ctypes import CDLL


class LowLevelLibs(object):

    def __init__(self):
        self.__lib_path = os.path.dirname(os.path.realpath(__file__))
        self.common = CDLL(os.path.join(self.__lib_path, "libvsc_common.dylib"))
        self.foundation = CDLL(os.path.join(self.__lib_path, "libvsc_foundation.dylib"))
        self.phe = CDLL(os.path.join(self.__lib_path, "libvsc_phe.dylib"))
