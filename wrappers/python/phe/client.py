from .buffer import Buffer
from .data import Data
from .phe import Phe


class Client(object):

    def __init__(self):
        self.__phe = Phe()

    def enroll_account(self, client_private_key, server_public_key, response, password):
        # type: (bytearray, bytearray, bytearray, bytearray) -> (bytearray, bytearray)
        client = self.__initiate_client(client_private_key, server_public_key)

        resp = Data(response)
        pwd = Data(password)
        enrollment_record = Buffer(self.__phe.vsce_phe_client_enrollment_record_len(client))

        key_buffer = Buffer(self.__phe.constants.PHE_ACCOUNT_KEY_LENGTH)

        err = self.__phe.vsce_phe_client_enroll_account(
            client,
            resp.data,
            pwd.data,
            enrollment_record.c_buffer,
            key_buffer.c_buffer
        )

        if err:
            raise RuntimeError("Could not create enrollment record")

        self.__phe.vsce_phe_client_destroy(client)
        return enrollment_record.get_data(), key_buffer.get_data()

    def password_verify_request(self, client_private_key, server_public_key, record, password):
        # type: (bytearray, bytearray, bytearray, bytearray) ->  bytearray
        client = self.__initiate_client(client_private_key, server_public_key)

        pwd = Data(password)
        rec = Data(record)
        req = Buffer(self.__phe.vsce_phe_client_verify_password_request_len(client))

        err = self.__phe.vsce_phe_client_create_verify_password_request(
            client,
            pwd.data,
            rec.data,
            req.c_buffer
        )

        if err:
            raise RuntimeError("Could not create password verify request")

        self.__phe.vsce_phe_client_destroy(client)
        return req.get_data()

    def verify_server_response(self, client_private_key, server_public_key, password, record, response):
        # type: (bytearray, bytearray, bytearray, bytearray, bytearray) -> bytearray
        client = self.__initiate_client(client_private_key, server_public_key)

        pwd = Data(password)
        rec = Data(record)
        resp = Data(response)

        key_buffer = Buffer(self.__phe.constants.PHE_ACCOUNT_KEY_LENGTH)

        err = self.__phe.vsce_phe_client_check_response_and_decrypt(
            client,
            pwd.data,
            rec.data,
            resp.data,
            key_buffer.c_buffer
        )

        if err:
            raise RuntimeError("Could not validate server response")

        self.__phe.vsce_phe_client_destroy(client)
        return key_buffer.get_data()

    def __initiate_client(self, client_private_key, server_public_key):
        sk = Data(client_private_key)
        pk = Data(server_public_key)
        client = self.__phe.vsce_phe_client_new()

        self.__phe.vsce_phe_client_set_keys(
            client,
            sk.data,
            pk.data
        )
        return client
