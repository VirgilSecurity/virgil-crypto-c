from .buffer import Buffer
from .data import Data
from .phe import Phe


class Server(object):

    def __init__(self):
        self.__phe = Phe()
        self.server = self.__phe.vsce_phe_server_new()

    def generate_server_keypair(self):
        # type: () -> [bytearray, bytearray]

        server_private_key = Buffer(self.__phe.constants.PHE_PRIVATE_KEY_LENGTH)
        server_public_key = Buffer(self.__phe.constants.PHE_PUBLIC_KEY_LENGTH)

        err = self.__phe.vsce_phe_server_generate_server_key_pair(
            self.server,
            server_private_key.c_buffer,
            server_public_key.c_buffer
        )

        if err:
            raise RuntimeError("Could not generate Key Pair")

        return server_private_key.get_data(), server_public_key.get_data()

    def get_enrollment(self, private_key, public_key):
        # type: (bytearray, bytearray) -> bytearray

        enrollment_buffer_size = self.__phe.vsce_phe_server_enrollment_response_len(self.server)
        enrollment_response = Buffer(int(enrollment_buffer_size))

        server_key = Data(private_key)
        pub_key = Data(public_key)

        err = self.__phe.vsce_phe_server_get_enrollment(
            self.server,
            server_key.data,
            pub_key.data,
            enrollment_response.c_buffer
        )

        if err:
            raise RuntimeError("Could not get enrollment")

        return enrollment_response.get_data()

    def verify_password(self, private_key, public_key, request):
        # type: (bytearray, bytearray, bytearray) -> bytearray
        server_key = Data(private_key)
        pub_key = Data(public_key)
        req = Data(request)

        verify_password_response = Buffer(self.__phe.vsce_phe_server_verify_password_response_len(self.server))

        err = self.__phe.vsce_phe_server_verify_password(
            self.server,
            server_key.data,
            pub_key.data,
            req.data,
            verify_password_response.c_buffer
        )

        if err:
            raise RuntimeError("Unable to make verify password response")

        return verify_password_response.get_data()
