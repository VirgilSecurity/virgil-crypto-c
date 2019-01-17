from ctypes import CDLL
from ctypes.util import find_library


class LowLevelLibs(object):

    def __init__(self):
        self._common = None
        self._foundation = None
        self._phe = None

    @property
    def common(self):
        if self._common is None:
            self._common = CDLL(find_library("libvsc_common.dylib"))
        return self._common

    @property
    def foundation(self):
        if self._foundation is None:
            self._foundation = CDLL(find_library("libvsc_foundation.dylib"))
        return self._foundation

    @property
    def phe(self):
        if self._phe is None:
            self._phe = CDLL(find_library("libvsc_phe.dylib"))
        return self._phe
