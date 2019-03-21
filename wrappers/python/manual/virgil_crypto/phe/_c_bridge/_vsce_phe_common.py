from enum import IntEnum


# C enum wrapper
class VscePheCommon(IntEnum):
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
    PHE_MAX_ENCRYPT_LEN = 1024 * 1024 - 64
    #
    #  Maximum data size to decrypt
    #
    PHE_MAX_DECRYPT_LEN = 1024 * 1024
