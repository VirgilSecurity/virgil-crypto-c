from virgil_crypto._libs import LowLevelLibs
from virgil_crypto.common._c_bridge import vsc_buffer_t, vsc_data_t
from ctypes import POINTER, Structure, c_size_t, c_int


class vsce_phe_server_t(Structure):
    pass


class VscePheServer(object):

    def __init__(self):
        self._lib = LowLevelLibs().phe

    def vsce_phe_server_new(self, *args, **kwargs):
        # vsce_phe_server_new C function wrapper
        vsce_phe_server_new = self._lib.vsce_phe_server_new
        vsce_phe_server_new.restype = POINTER(vsce_phe_server_t)
        return vsce_phe_server_new(*args, **kwargs)

    def vsce_phe_server_generate_server_key_pair(self, *args, **kwargs):
        # vsce_phe_server_generate_server_key_pair C function wrapper
        vsce_phe_server_generate_server_key_pair = self._lib.vsce_phe_server_generate_server_key_pair
        vsce_phe_server_generate_server_key_pair.argtypes = [
            POINTER(vsce_phe_server_t),
            POINTER(vsc_buffer_t),
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_server_generate_server_key_pair.restype = c_int
        return vsce_phe_server_generate_server_key_pair(*args, **kwargs)

    def vsce_phe_server_enrollment_response_len(self, *args, **kwargs):
        # vsce_phe_server_enrollment_response_len C function wrapper
        vsce_phe_server_enrollment_response_len = self._lib.vsce_phe_server_enrollment_response_len
        vsce_phe_server_enrollment_response_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_enrollment_response_len.restype = c_size_t
        return vsce_phe_server_enrollment_response_len(*args, **kwargs)

    def vsce_phe_server_get_enrollment(self, *args, **kwargs):
        # vsce_phe_server_get_enrollment C function wrapper
        vsce_phe_server_get_enrollment = self._lib.vsce_phe_server_get_enrollment
        vsce_phe_server_get_enrollment.argtypes = [
            POINTER(vsce_phe_server_t),
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_server_get_enrollment.restype = c_int
        return vsce_phe_server_get_enrollment(*args, **kwargs)

    def vsce_phe_server_verify_password(self, *args, **kwargs):
        # vsce_phe_server_verify_password C function wrapper
        vsce_phe_server_verify_password = self._lib.vsce_phe_server_verify_password
        vsce_phe_server_verify_password.argtypes = [
            POINTER(vsce_phe_server_t),
            vsc_data_t,
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_server_verify_password.restype = c_int
        return vsce_phe_server_verify_password(*args, **kwargs)

    def vsce_phe_server_verify_password_response_len(self, *args, **kwargs):
        # vsce_phe_server_verify_password_response_len
        vsce_phe_server_verify_password_response_len = self._lib.vsce_phe_server_verify_password_response_len
        vsce_phe_server_verify_password_response_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_verify_password_response_len.restype = c_size_t
        return vsce_phe_server_verify_password_response_len(*args, **kwargs)