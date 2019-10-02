from virgil_crypto._libs import LowLevelLibs
from virgil_crypto.common._c_bridge import vsc_data_t,vsc_buffer_t
from ctypes import Structure, POINTER, c_size_t, c_int


# C structure wrapper
class vsce_phe_client_t(Structure):
    pass


class VscePheClient(object):

    def __init__(self):
        self._lib = LowLevelLibs().phe

    def vsce_phe_client_new(self):
        # vsce_phe_client_new C function wrapper
        vsce_phe_client_new = self._lib.vsce_phe_client_new
        vsce_phe_client_new.restype = POINTER(vsce_phe_client_t)
        return vsce_phe_client_new()

    def vsce_phe_client_destroy(self, client):
        # vsce_phe_client_destroy C function wrapper
        vsce_phe_client_destroy = self._lib.vsce_phe_client_destroy
        vsce_phe_client_destroy.argtypes = [POINTER(POINTER(vsce_phe_client_t))]
        vsce_phe_client_destroy.restype = None
        return vsce_phe_client_destroy(client)

    def vsce_phe_client_set_keys(self, *args, **kwargs):
        # vsce_phe_client_set_keys C function wrapper
        vsce_phe_client_set_keys = self._lib.vsce_phe_client_set_keys
        vsce_phe_client_set_keys.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t
        ]
        vsce_phe_client_set_keys.restype = c_int
        return vsce_phe_client_set_keys(*args, **kwargs)

    def vsce_phe_client_enrollment_record_len(self, client):
        # vsce_phe_client_enrollment_record_len C function wrapper
        vsce_phe_client_enrollment_record_len = self._lib.vsce_phe_client_enrollment_record_len
        vsce_phe_client_enrollment_record_len.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_enrollment_record_len.restype = c_size_t
        return vsce_phe_client_enrollment_record_len(client)

    def vsce_phe_client_enroll_account(self, *args, **kwargs):
        # vsce_phe_client_enroll_account C function wrapper
        vsce_phe_client_enroll_account = self._lib.vsce_phe_client_enroll_account
        vsce_phe_client_enroll_account.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t),
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_client_enroll_account.restype = c_int
        return vsce_phe_client_enroll_account(*args, **kwargs)

    def vsce_phe_client_verify_password_request_len(self, client):
        # vsce_phe_client_password_verify_request_len C function wrapper
        vsce_phe_client_verify_password_request_len = self._lib.vsce_phe_client_verify_password_request_len
        vsce_phe_client_verify_password_request_len.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_verify_password_request_len.restype = c_size_t
        return vsce_phe_client_verify_password_request_len(client)

    def vsce_phe_client_create_verify_password_request(self, *args, **kwargs):
        # vsce_phe_client_create_verify_password_request
        vsce_phe_client_create_verify_password_request = self._lib.vsce_phe_client_create_verify_password_request
        vsce_phe_client_create_verify_password_request.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_client_create_verify_password_request.restype = c_int
        return vsce_phe_client_create_verify_password_request(*args, **kwargs)

    def vsce_phe_client_check_response_and_decrypt(self, *args, **kwargs):
        # vsce_phe_client_check_response_and_decrypt C function wrapper
        vsce_phe_client_check_response_and_decrypt = self._lib.vsce_phe_client_check_response_and_decrypt
        vsce_phe_client_check_response_and_decrypt.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_client_check_response_and_decrypt.restype = c_int
        return vsce_phe_client_check_response_and_decrypt(*args, **kwargs)