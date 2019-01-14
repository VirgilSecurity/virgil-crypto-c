import os
from ctypes import c_int, CDLL, Structure, c_byte, c_size_t, POINTER
from ctypes.util import find_library
from enum import IntEnum


class CtypesEnum(IntEnum):
    """A ctypes-compatible IntEnum superclass."""
    @classmethod
    def from_param(cls, obj):
        return int(obj)


# C enum wrapper
class PHEConstants(CtypesEnum):
    #  PHE elliptic curve point binary length
    #
    PHE_POINT_LENGTH = 65
    #
    #  PHE max password length
    #
    PHE_MAX_PASSWORD_LENGTH = 128
    #
    #  PHE server identifier length
    #
    PHE_SERVER_IDENTIFIER_LENGTH = 32
    #
    #  PHE client identifier length
    #
    PHE_CLIENT_IDENTIFIER_LENGTH = 32
    #
    #  PHE account key length
    #
    PHE_ACCOUNT_KEY_LENGTH = 32
    #
    #  PHE private key length
    #
    PHE_PRIVATE_KEY_LENGTH = 32
    #
    #  PHE public key length
    #
    PHE_PUBLIC_KEY_LENGTH = 65
    #
    #  PHE hash length
    #
    PHE_HASH_LEN = 32
    #
    #  Maximum data size to encrypt
    #
    vsce_phe_common_PHE_MAX_ENCRYPT_LEN = 1024 * 1024 - 64
    #
    #  Maximum data size to decrypt
    #
    PHE_MAX_DECRYPT_LEN = 1024 * 1024


# C structure wrapper
class vsc_buffer_t(Structure):
    pass


# C structure wrapper
class vsce_phe_server_t(Structure):
    pass


# C structure wrapper
class vsce_error_t(Structure):
    pass


# C structure wrapper
class vsce_phe_client_t(Structure):
    pass


# C structure wrapper
class vsc_data_t(Structure):
    _fields_ = [
        ("bytes", POINTER(c_byte)),
        ("len", c_size_t)
    ]


# C library wrapper
class Phe(object):
    def __init__(self):
        self.constants = PHEConstants
        self.__c_common_lib = CDLL(find_library("libvsc_common.dylib"))
        self.__c_foundation_lib = CDLL(find_library("libvsc_foundation.dylib"))
        self.__c_lib = CDLL(find_library("libvsc_phe.dylib"))

    def vsc_buffer_new(self):
        # vsc_buffer_new C function wrapper
        vsc_buffer_new = self.__c_lib.vsc_buffer_new
        vsc_buffer_new.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_new()

    def vsc_buffer_new_with_data(self, *args, **kwargs):
        # vsc_buffer_new_with_data C function wrapper
        vsc_buffer_new_with_data = self.__c_lib.vsc_buffer_new_with_data
        vsc_buffer_new_with_data.argtypes = [vsc_data_t]
        vsc_buffer_new_with_data.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_new_with_data(*args, **kwargs)

    def vsc_buffer_use(self, *args, **kwargs):
        # vsc_buffer_use C function wrapper
        vsc_buffer_use = self.__c_lib.vsc_buffer_use
        vsc_buffer_use.argtypes = [
            POINTER(vsc_buffer_t),
            POINTER(c_byte),
            c_size_t
        ]
        return vsc_buffer_use(*args, **kwargs)

    def vsc_data(self, *args, **kwargs):
        # vsc_data C function wrapper
        vsc_data = self.__c_lib.vsc_data
        vsc_data.argtypes = [
            POINTER(c_byte),
            c_size_t
        ]
        vsc_data.restype = vsc_data_t
        return vsc_data(*args, **kwargs)

    def vsc_buffer_destroy(self, *args, **kwargs):
        # vsc_buffer_destroy C function wrapper
        vsc_buffer_destroy = self.__c_lib.vsc_buffer_destroy
        vsc_buffer_destroy.argtypes = [POINTER(POINTER(vsc_buffer_t))]
        return vsc_buffer_destroy(*args, **kwargs)

    def vsce_phe_server_new(self, *args, **kwargs):
        # vsce_phe_server_new C function wrapper
        vsce_phe_server_new = self.__c_lib.vsce_phe_server_new
        vsce_phe_server_new.restype = POINTER(vsce_phe_server_t)
        return vsce_phe_server_new(*args, **kwargs)

    def vsce_phe_server_generate_server_key_pair(self, *args, **kwargs):
        # vsce_phe_server_generate_server_key_pair C function wrapper
        vsce_phe_server_generate_server_key_pair = self.__c_lib.vsce_phe_server_generate_server_key_pair
        vsce_phe_server_generate_server_key_pair.argtypes = [
            POINTER(vsce_phe_server_t),
            POINTER(vsc_buffer_t),
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_server_generate_server_key_pair.restype = c_int
        return vsce_phe_server_generate_server_key_pair(*args, **kwargs)

    def vsce_phe_server_enrollment_response_len(self, *args, **kwargs):
        # vsce_phe_server_enrollment_response_len C function wrapper
        vsce_phe_server_enrollment_response_len = self.__c_lib.vsce_phe_server_enrollment_response_len
        vsce_phe_server_enrollment_response_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_enrollment_response_len.restype = c_size_t
        return vsce_phe_server_enrollment_response_len(*args, **kwargs)

    def vsce_phe_server_get_enrollment(self, *args, **kwargs):
        # vsce_phe_server_get_enrollment C function wrapper
        vsce_phe_server_get_enrollment = self.__c_lib.vsce_phe_server_get_enrollment
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
        vsce_phe_server_verify_password = self.__c_lib.vsce_phe_server_verify_password
        vsce_phe_server_verify_password.argtypes = [
            POINTER(vsce_phe_server_t),
            vsc_data_t,
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_server_verify_password.restype = c_int
        return vsce_phe_server_verify_password(*args, **kwargs)

    def vsce_phe_client_new(self, *args, **kwargs):
        # vsce_phe_client_new C function wrapper
        vsce_phe_client_new = self.__c_lib.vsce_phe_client_new
        vsce_phe_client_new.restype = POINTER(vsce_phe_client_t)
        return vsce_phe_client_new(*args, **kwargs)

    def vsce_phe_client_destroy(self, *args, **kwargs):
        # vsce_phe_client_destroy C function wrapper
        vsce_phe_client_destroy = self.__c_lib.vsce_phe_client_destroy
        vsce_phe_client_destroy.argtypes = [POINTER(POINTER(vsce_phe_client_t))]
        vsce_phe_client_destroy.restype = None
        return vsce_phe_client_destroy(*args, **kwargs)

    def vsce_phe_client_set_keys(self, *args, **kwargs):
        # vsce_phe_client_set_keys C function wrapper
        vsce_phe_client_set_keys = self.__c_lib.vsce_phe_client_set_keys
        vsce_phe_client_set_keys.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t
        ]
        vsce_phe_client_set_keys.restype = c_int
        return vsce_phe_client_set_keys(*args, **kwargs)

    def vsce_phe_client_enrollment_record_len(self, *args, **kwargs):
        # vsce_phe_client_enrollment_record_len C function wrapper
        vsce_phe_client_enrollment_record_len = self.__c_lib.vsce_phe_client_enrollment_record_len
        vsce_phe_client_enrollment_record_len.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_enrollment_record_len.restype = c_size_t
        return vsce_phe_client_enrollment_record_len(*args, **kwargs)

    def vsce_phe_client_enroll_account(self, *args, **kwargs):
        # vsce_phe_client_enroll_account C function wrapper
        vsce_phe_client_enroll_account = self.__c_lib.vsce_phe_client_enroll_account
        vsce_phe_client_enroll_account.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t),
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_client_enroll_account.restype = c_int
        return vsce_phe_client_enroll_account(*args, **kwargs)

    def vsce_phe_client_verify_password_request_len(self, *args, **kwargs):
        # vsce_phe_client_password_verify_request_len C function wrapper
        vsce_phe_client_verify_password_request_len = self.__c_lib.vsce_phe_client_verify_password_request_len
        vsce_phe_client_verify_password_request_len.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_verify_password_request_len.restype = c_size_t
        return vsce_phe_client_verify_password_request_len(*args, **kwargs)

    def vsce_phe_client_create_verify_password_request(self, *args, **kwargs):
        # vsce_phe_client_create_verify_password_request
        vsce_phe_client_create_verify_password_request = self.__c_lib.vsce_phe_client_create_verify_password_request
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
        vsce_phe_client_check_response_and_decrypt = self.__c_lib.vsce_phe_client_check_response_and_decrypt
        vsce_phe_client_check_response_and_decrypt.argtypes = [
            POINTER(vsce_phe_client_t),
            vsc_data_t,
            vsc_data_t,
            vsc_data_t,
            POINTER(vsc_buffer_t)
        ]
        vsce_phe_client_check_response_and_decrypt.restype = c_int
        return vsce_phe_client_check_response_and_decrypt(*args, **kwargs)

    def vsce_phe_server_verify_password_response_len(self, *args, **kwargs):
        # vsce_phe_server_verify_password_response_len
        vsce_phe_server_verify_password_response_len = self.__c_lib.vsce_phe_server_verify_password_response_len
        vsce_phe_server_verify_password_response_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_verify_password_response_len.restype = c_size_t
        return vsce_phe_server_verify_password_response_len(*args, **kwargs)
