/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

package com.virgilsecurity.crypto.foundation;

/*
* Defines the library status codes.
*/
public class FoundationException extends RuntimeException {

    public static final int SUCCESS = 0;

    public static final int ERROR_BAD_ARGUMENTS = -1;

    public static final int ERROR_UNINITIALIZED = -2;

    public static final int ERROR_UNHANDLED_THIRDPARTY_ERROR = -3;

    public static final int ERROR_SMALL_BUFFER = -101;

    public static final int ERROR_UNSUPPORTED_ALGORITHM = -200;

    public static final int ERROR_AUTH_FAILED = -201;

    public static final int ERROR_OUT_OF_DATA = -202;

    public static final int ERROR_BAD_ASN1 = -203;

    public static final int ERROR_ASN1_LOSSY_TYPE_NARROWING = -204;

    public static final int ERROR_BAD_PKCS1_PUBLIC_KEY = -205;

    public static final int ERROR_BAD_PKCS1_PRIVATE_KEY = -206;

    public static final int ERROR_BAD_PKCS8_PUBLIC_KEY = -207;

    public static final int ERROR_BAD_PKCS8_PRIVATE_KEY = -208;

    public static final int ERROR_BAD_ENCRYPTED_DATA = -209;

    public static final int ERROR_RANDOM_FAILED = -210;

    public static final int ERROR_KEY_GENERATION_FAILED = -211;

    public static final int ERROR_ENTROPY_SOURCE_FAILED = -212;

    public static final int ERROR_RNG_REQUESTED_DATA_TOO_BIG = -213;

    public static final int ERROR_BAD_BASE64 = -214;

    public static final int ERROR_BAD_PEM = -215;

    public static final int ERROR_SHARED_KEY_EXCHANGE_FAILED = -216;

    public static final int ERROR_BAD_ED25519_PUBLIC_KEY = -217;

    public static final int ERROR_BAD_ED25519_PRIVATE_KEY = -218;

    public static final int ERROR_BAD_CURVE25519_PUBLIC_KEY = -219;

    public static final int ERROR_BAD_CURVE25519_PRIVATE_KEY = -220;

    public static final int ERROR_BAD_SEC1_PUBLIC_KEY = -221;

    public static final int ERROR_BAD_SEC1_PRIVATE_KEY = -222;

    public static final int ERROR_BAD_DER_PUBLIC_KEY = -223;

    public static final int ERROR_BAD_DER_PRIVATE_KEY = -224;

    public static final int ERROR_NO_MESSAGE_INFO = -301;

    public static final int ERROR_BAD_MESSAGE_INFO = -302;

    public static final int ERROR_KEY_RECIPIENT_IS_NOT_FOUND = -303;

    public static final int ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG = -304;

    public static final int ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG = -305;

    public static final int ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND = -306;

    public static final int ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH = -307;

    public static final int ERROR_BAD_SIGNATURE = -308;

    public static final int ERROR_INVALID_BRAINKEY_PASSWORD_LEN = -401;

    public static final int ERROR_INVALID_BRAINKEY_FACTOR_LEN = -402;

    public static final int ERROR_INVALID_BRAINKEY_POINT_LEN = -403;

    public static final int ERROR_INVALID_BRAINKEY_KEY_NAME_LEN = -404;

    public static final int ERROR_BRAINKEY_INTERNAL = -405;

    public static final int ERROR_BRAINKEY_INVALID_POINT = -406;

    public static final int ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN = -407;

    public static final int ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN = -408;

    public static final int ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN = -409;

    public static final int ERROR_INVALID_IDENTITY_SECRET = -410;

    private int statusCode;

    /* Create new instance. */
    public FoundationException(int statusCode) {
        super();
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public String getMessage() {
        switch (this.statusCode) {
        case SUCCESS:
            return "No errors was occurred.";
        case ERROR_BAD_ARGUMENTS:
            return "This error should not be returned if assertions is enabled.";
        case ERROR_UNINITIALIZED:
            return "Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.";
        case ERROR_UNHANDLED_THIRDPARTY_ERROR:
            return "Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.";
        case ERROR_SMALL_BUFFER:
            return "Buffer capacity is not enough to hold result.";
        case ERROR_UNSUPPORTED_ALGORITHM:
            return "Unsupported algorithm.";
        case ERROR_AUTH_FAILED:
            return "Authentication failed during decryption.";
        case ERROR_OUT_OF_DATA:
            return "Attempt to read data out of buffer bounds.";
        case ERROR_BAD_ASN1:
            return "ASN.1 encoded data is corrupted.";
        case ERROR_ASN1_LOSSY_TYPE_NARROWING:
            return "Attempt to read ASN.1 type that is bigger then requested C type.";
        case ERROR_BAD_PKCS1_PUBLIC_KEY:
            return "ASN.1 representation of PKCS#1 public key is corrupted.";
        case ERROR_BAD_PKCS1_PRIVATE_KEY:
            return "ASN.1 representation of PKCS#1 private key is corrupted.";
        case ERROR_BAD_PKCS8_PUBLIC_KEY:
            return "ASN.1 representation of PKCS#8 public key is corrupted.";
        case ERROR_BAD_PKCS8_PRIVATE_KEY:
            return "ASN.1 representation of PKCS#8 private key is corrupted.";
        case ERROR_BAD_ENCRYPTED_DATA:
            return "Encrypted data is corrupted.";
        case ERROR_RANDOM_FAILED:
            return "Underlying random operation returns error.";
        case ERROR_KEY_GENERATION_FAILED:
            return "Generation of the private or secret key failed.";
        case ERROR_ENTROPY_SOURCE_FAILED:
            return "One of the entropy sources failed.";
        case ERROR_RNG_REQUESTED_DATA_TOO_BIG:
            return "Requested data to be generated is too big.";
        case ERROR_BAD_BASE64:
            return "Base64 encoded string contains invalid characters.";
        case ERROR_BAD_PEM:
            return "PEM data is corrupted.";
        case ERROR_SHARED_KEY_EXCHANGE_FAILED:
            return "Exchange key return zero.";
        case ERROR_BAD_ED25519_PUBLIC_KEY:
            return "Ed25519 public key is corrupted.";
        case ERROR_BAD_ED25519_PRIVATE_KEY:
            return "Ed25519 private key is corrupted.";
        case ERROR_BAD_CURVE25519_PUBLIC_KEY:
            return "CURVE25519 public key is corrupted.";
        case ERROR_BAD_CURVE25519_PRIVATE_KEY:
            return "CURVE25519 private key is corrupted.";
        case ERROR_BAD_SEC1_PUBLIC_KEY:
            return "Elliptic curve public key format is corrupted see RFC 5480.";
        case ERROR_BAD_SEC1_PRIVATE_KEY:
            return "Elliptic curve public key format is corrupted see RFC 5915.";
        case ERROR_BAD_DER_PUBLIC_KEY:
            return "ASN.1 representation of a public key is corrupted.";
        case ERROR_BAD_DER_PRIVATE_KEY:
            return "ASN.1 representation of a private key is corrupted.";
        case ERROR_NO_MESSAGE_INFO:
            return "Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.";
        case ERROR_BAD_MESSAGE_INFO:
            return "Message info is corrupted.";
        case ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
            return "Recipient defined with id is not found within message info during data decryption.";
        case ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
            return "Content encryption key can not be decrypted with a given private key.";
        case ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG:
            return "Content encryption key can not be decrypted with a given password.";
        case ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND:
            return "Custom parameter with a given key is not found within message info.";
        case ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH:
            return "A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.";
        case ERROR_BAD_SIGNATURE:
            return "Signature format is corrupted.";
        case ERROR_INVALID_BRAINKEY_PASSWORD_LEN:
            return "Brainkey password length is out of range.";
        case ERROR_INVALID_BRAINKEY_FACTOR_LEN:
            return "Brainkey number length should be 32 byte.";
        case ERROR_INVALID_BRAINKEY_POINT_LEN:
            return "Brainkey point length should be 65 bytes.";
        case ERROR_INVALID_BRAINKEY_KEY_NAME_LEN:
            return "Brainkey name is out of range.";
        case ERROR_BRAINKEY_INTERNAL:
            return "Brainkey internal error.";
        case ERROR_BRAINKEY_INVALID_POINT:
            return "Brainkey point is invalid.";
        case ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN:
            return "Brainkey number buffer length capacity should be >= 32 byte.";
        case ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN:
            return "Brainkey point buffer length capacity should be >= 32 byte.";
        case ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN:
            return "Brainkey seed buffer length capacity should be >= 32 byte.";
        case ERROR_INVALID_IDENTITY_SECRET:
            return "Brainkey identity secret is invalid.";
        default:
            return "Unknown error";
        }
    }
}

