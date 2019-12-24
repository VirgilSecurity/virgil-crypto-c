# Copyright (C) 2015-2019 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from ctypes import *


class VirgilCryptoFoundationError(Exception):
    pass


class Status(object):
    """Defines the library status codes."""

    # No errors was occurred.
    SUCCESS = 0
    # This error should not be returned if assertions is enabled.
    ERROR_BAD_ARGUMENTS = -1
    # Can be used to define that not all context prerequisites are satisfied.
    # Note, this error should not be returned if assertions is enabled.
    ERROR_UNINITIALIZED = -2
    # Define that error code from one of third-party module was not handled.
    # Note, this error should not be returned if assertions is enabled.
    ERROR_UNHANDLED_THIRDPARTY_ERROR = -3
    # Buffer capacity is not enough to hold result.
    ERROR_SMALL_BUFFER = -101
    # Unsupported algorithm.
    ERROR_UNSUPPORTED_ALGORITHM = -200
    # Authentication failed during decryption.
    ERROR_AUTH_FAILED = -201
    # Attempt to read data out of buffer bounds.
    ERROR_OUT_OF_DATA = -202
    # ASN.1 encoded data is corrupted.
    ERROR_BAD_ASN1 = -203
    # Attempt to read ASN.1 type that is bigger then requested C type.
    ERROR_ASN1_LOSSY_TYPE_NARROWING = -204
    # ASN.1 representation of PKCS#1 public key is corrupted.
    ERROR_BAD_PKCS1_PUBLIC_KEY = -205
    # ASN.1 representation of PKCS#1 private key is corrupted.
    ERROR_BAD_PKCS1_PRIVATE_KEY = -206
    # ASN.1 representation of PKCS#8 public key is corrupted.
    ERROR_BAD_PKCS8_PUBLIC_KEY = -207
    # ASN.1 representation of PKCS#8 private key is corrupted.
    ERROR_BAD_PKCS8_PRIVATE_KEY = -208
    # Encrypted data is corrupted.
    ERROR_BAD_ENCRYPTED_DATA = -209
    # Underlying random operation returns error.
    ERROR_RANDOM_FAILED = -210
    # Generation of the private or secret key failed.
    ERROR_KEY_GENERATION_FAILED = -211
    # One of the entropy sources failed.
    ERROR_ENTROPY_SOURCE_FAILED = -212
    # Requested data to be generated is too big.
    ERROR_RNG_REQUESTED_DATA_TOO_BIG = -213
    # Base64 encoded string contains invalid characters.
    ERROR_BAD_BASE64 = -214
    # PEM data is corrupted.
    ERROR_BAD_PEM = -215
    # Exchange key return zero.
    ERROR_SHARED_KEY_EXCHANGE_FAILED = -216
    # Ed25519 public key is corrupted.
    ERROR_BAD_ED25519_PUBLIC_KEY = -217
    # Ed25519 private key is corrupted.
    ERROR_BAD_ED25519_PRIVATE_KEY = -218
    # CURVE25519 public key is corrupted.
    ERROR_BAD_CURVE25519_PUBLIC_KEY = -219
    # CURVE25519 private key is corrupted.
    ERROR_BAD_CURVE25519_PRIVATE_KEY = -220
    # Elliptic curve public key format is corrupted see RFC 5480.
    ERROR_BAD_SEC1_PUBLIC_KEY = -221
    # Elliptic curve public key format is corrupted see RFC 5915.
    ERROR_BAD_SEC1_PRIVATE_KEY = -222
    # ASN.1 representation of a public key is corrupted.
    ERROR_BAD_DER_PUBLIC_KEY = -223
    # ASN.1 representation of a private key is corrupted.
    ERROR_BAD_DER_PRIVATE_KEY = -224
    # Key algorithm does not accept given type of public key.
    ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM = -225
    # Key algorithm does not accept given type of private key.
    ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM = -226
    # Post-quantum Falcon-Sign public key is corrupted.
    ERROR_BAD_FALCON_PUBLIC_KEY = -227
    # Post-quantum Falcon-Sign private key is corrupted.
    ERROR_BAD_FALCON_PRIVATE_KEY = -228
    # Generic Round5 library error.
    ERROR_ROUND5 = -229
    # Post-quantum NIST Round5 public key is corrupted.
    ERROR_BAD_ROUND5_PUBLIC_KEY = -230
    # Post-quantum NIST Round5 private key is corrupted.
    ERROR_BAD_ROUND5_PRIVATE_KEY = -231
    # Compound public key is corrupted.
    ERROR_BAD_COMPOUND_PUBLIC_KEY = -232
    # Compound private key is corrupted.
    ERROR_BAD_COMPOUND_PRIVATE_KEY = -233
    # Compound public hybrid key is corrupted.
    ERROR_BAD_HYBRID_PUBLIC_KEY = -234
    # Compound private hybrid key is corrupted.
    ERROR_BAD_HYBRID_PRIVATE_KEY = -235
    # ASN.1 AlgorithmIdentifer is corrupted.
    ERROR_BAD_ASN1_ALGORITHM = -236
    # ASN.1 AlgorithmIdentifer with ECParameters is corrupted.
    ERROR_BAD_ASN1_ALGORITHM_ECC = -237
    # ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.
    ERROR_BAD_ASN1_ALGORITHM_COMPOUND_KEY = -238
    # ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.
    ERROR_BAD_ASN1_ALGORITHM_HYBRID_KEY = -239
    # Decryption failed, because message info was not given explicitly,
    # and was not part of an encrypted message.
    ERROR_NO_MESSAGE_INFO = -301
    # Message Info is corrupted.
    ERROR_BAD_MESSAGE_INFO = -302
    # Recipient defined with id is not found within message info
    # during data decryption.
    ERROR_KEY_RECIPIENT_IS_NOT_FOUND = -303
    # Content encryption key can not be decrypted with a given private key.
    ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG = -304
    # Content encryption key can not be decrypted with a given password.
    ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG = -305
    # Custom parameter with a given key is not found within message info.
    ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND = -306
    # A custom parameter with a given key is found, but the requested value
    # type does not correspond to the actual type.
    ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH = -307
    # Signature format is corrupted.
    ERROR_BAD_SIGNATURE = -308
    # Message Info footer is corrupted.
    ERROR_BAD_MESSAGE_INFO_FOOTER = -309
    # Brainkey password length is out of range.
    ERROR_INVALID_BRAINKEY_PASSWORD_LEN = -401
    # Brainkey number length should be 32 byte.
    ERROR_INVALID_BRAINKEY_FACTOR_LEN = -402
    # Brainkey point length should be 65 bytes.
    ERROR_INVALID_BRAINKEY_POINT_LEN = -403
    # Brainkey name is out of range.
    ERROR_INVALID_BRAINKEY_KEY_NAME_LEN = -404
    # Brainkey internal error.
    ERROR_BRAINKEY_INTERNAL = -405
    # Brainkey point is invalid.
    ERROR_BRAINKEY_INVALID_POINT = -406
    # Brainkey number buffer length capacity should be >= 32 byte.
    ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN = -407
    # Brainkey point buffer length capacity should be >= 32 byte.
    ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN = -408
    # Brainkey seed buffer length capacity should be >= 32 byte.
    ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN = -409
    # Brainkey identity secret is invalid.
    ERROR_INVALID_IDENTITY_SECRET = -410
    # KEM encapsulated key is invalid or does not correspond to the private key.
    ERROR_INVALID_KEM_ENCAPSULATED_KEY = -411
    # Invalid padding.
    ERROR_INVALID_PADDING = -501
    # Protobuf error.
    ERROR_PROTOBUF = -601
    # Session id doesnt match.
    ERROR_SESSION_ID_DOESNT_MATCH = -701
    # Epoch not found.
    ERROR_EPOCH_NOT_FOUND = -702
    # Wrong key type.
    ERROR_WRONG_KEY_TYPE = -703
    # Invalid signature.
    ERROR_INVALID_SIGNATURE = -704
    # Ed25519 error.
    ERROR_ED25519 = -705
    # Duplicate epoch.
    ERROR_DUPLICATE_EPOCH = -706
    # Plain text too long.
    ERROR_PLAIN_TEXT_TOO_LONG = -707

    STATUS_DICT = {
        0: "No errors was occurred.",
        -1: "This error should not be returned if assertions is enabled.",
        -2: "Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.",
        -3: "Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.",
        -101: "Buffer capacity is not enough to hold result.",
        -200: "Unsupported algorithm.",
        -201: "Authentication failed during decryption.",
        -202: "Attempt to read data out of buffer bounds.",
        -203: "ASN.1 encoded data is corrupted.",
        -204: "Attempt to read ASN.1 type that is bigger then requested C type.",
        -205: "ASN.1 representation of PKCS#1 public key is corrupted.",
        -206: "ASN.1 representation of PKCS#1 private key is corrupted.",
        -207: "ASN.1 representation of PKCS#8 public key is corrupted.",
        -208: "ASN.1 representation of PKCS#8 private key is corrupted.",
        -209: "Encrypted data is corrupted.",
        -210: "Underlying random operation returns error.",
        -211: "Generation of the private or secret key failed.",
        -212: "One of the entropy sources failed.",
        -213: "Requested data to be generated is too big.",
        -214: "Base64 encoded string contains invalid characters.",
        -215: "PEM data is corrupted.",
        -216: "Exchange key return zero.",
        -217: "Ed25519 public key is corrupted.",
        -218: "Ed25519 private key is corrupted.",
        -219: "CURVE25519 public key is corrupted.",
        -220: "CURVE25519 private key is corrupted.",
        -221: "Elliptic curve public key format is corrupted see RFC 5480.",
        -222: "Elliptic curve public key format is corrupted see RFC 5915.",
        -223: "ASN.1 representation of a public key is corrupted.",
        -224: "ASN.1 representation of a private key is corrupted.",
        -225: "Key algorithm does not accept given type of public key.",
        -226: "Key algorithm does not accept given type of private key.",
        -227: "Post-quantum Falcon-Sign public key is corrupted.",
        -228: "Post-quantum Falcon-Sign private key is corrupted.",
        -229: "Generic Round5 library error.",
        -230: "Post-quantum NIST Round5 public key is corrupted.",
        -231: "Post-quantum NIST Round5 private key is corrupted.",
        -232: "Compound public key is corrupted.",
        -233: "Compound private key is corrupted.",
        -234: "Compound public hybrid key is corrupted.",
        -235: "Compound private hybrid key is corrupted.",
        -236: "ASN.1 AlgorithmIdentifer is corrupted.",
        -237: "ASN.1 AlgorithmIdentifer with ECParameters is corrupted.",
        -238: "ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.",
        -239: "ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.",
        -301: "Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.",
        -302: "Message Info is corrupted.",
        -303: "Recipient defined with id is not found within message info during data decryption.",
        -304: "Content encryption key can not be decrypted with a given private key.",
        -305: "Content encryption key can not be decrypted with a given password.",
        -306: "Custom parameter with a given key is not found within message info.",
        -307: "A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.",
        -308: "Signature format is corrupted.",
        -309: "Message Info footer is corrupted.",
        -401: "Brainkey password length is out of range.",
        -402: "Brainkey number length should be 32 byte.",
        -403: "Brainkey point length should be 65 bytes.",
        -404: "Brainkey name is out of range.",
        -405: "Brainkey internal error.",
        -406: "Brainkey point is invalid.",
        -407: "Brainkey number buffer length capacity should be >= 32 byte.",
        -408: "Brainkey point buffer length capacity should be >= 32 byte.",
        -409: "Brainkey seed buffer length capacity should be >= 32 byte.",
        -410: "Brainkey identity secret is invalid.",
        -411: "KEM encapsulated key is invalid or does not correspond to the private key.",
        -501: "Invalid padding.",
        -601: "Protobuf error.",
        -701: "Session id doesnt match.",
        -702: "Epoch not found.",
        -703: "Wrong key type.",
        -704: "Invalid signature.",
        -705: "Ed25519 error.",
        -706: "Duplicate epoch.",
        -707: "Plain text too long."
    }

    @classmethod
    def handle_status(cls, status):
        """Handle low level lib status"""
        if status != 0:
            try:
                raise VirgilCryptoFoundationError(cls.STATUS_DICT[status])
            except KeyError:
                raise VirgilCryptoFoundationError("Unknown error")
