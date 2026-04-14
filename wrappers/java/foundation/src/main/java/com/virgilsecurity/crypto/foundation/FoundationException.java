/*
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

public class FoundationException {

    public int SUCCESS;

    public int ERROR_BAD_ARGUMENTS;

    public int ERROR_UNINITIALIZED;

    public int ERROR_UNHANDLED_THIRDPARTY_ERROR;

    public int ERROR_SMALL_BUFFER;

    public int ERROR_UNSUPPORTED_ALGORITHM;

    public int ERROR_AUTH_FAILED;

    public int ERROR_OUT_OF_DATA;

    public int ERROR_BAD_ASN1;

    public int ERROR_ASN1_LOSSY_TYPE_NARROWING;

    public int ERROR_BAD_PKCS1_PUBLIC_KEY;

    public int ERROR_BAD_PKCS1_PRIVATE_KEY;

    public int ERROR_BAD_PKCS8_PUBLIC_KEY;

    public int ERROR_BAD_PKCS8_PRIVATE_KEY;

    public int ERROR_BAD_ENCRYPTED_DATA;

    public int ERROR_RANDOM_FAILED;

    public int ERROR_KEY_GENERATION_FAILED;

    public int ERROR_ENTROPY_SOURCE_FAILED;

    public int ERROR_RNG_REQUESTED_DATA_TOO_BIG;

    public int ERROR_BAD_BASE64;

    public int ERROR_BAD_PEM;

    public int ERROR_SHARED_KEY_EXCHANGE_FAILED;

    public int ERROR_BAD_ED25519_PUBLIC_KEY;

    public int ERROR_BAD_ED25519_PRIVATE_KEY;

    public int ERROR_BAD_CURVE25519_PUBLIC_KEY;

    public int ERROR_BAD_CURVE25519_PRIVATE_KEY;

    public int ERROR_BAD_SEC1_PUBLIC_KEY;

    public int ERROR_BAD_SEC1_PRIVATE_KEY;

    public int ERROR_BAD_DER_PUBLIC_KEY;

    public int ERROR_BAD_DER_PRIVATE_KEY;

    public int ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;

    public int ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM;

    public int ERROR_BAD_FALCON_PUBLIC_KEY;

    public int ERROR_BAD_FALCON_PRIVATE_KEY;

    public int ERROR_ROUND5;

    public int ERROR_BAD_ROUND5_PUBLIC_KEY;

    public int ERROR_BAD_ROUND5_PRIVATE_KEY;

    public int ERROR_BAD_COMPOUND_PUBLIC_KEY;

    public int ERROR_BAD_COMPOUND_PRIVATE_KEY;

    public int ERROR_BAD_HYBRID_PUBLIC_KEY;

    public int ERROR_BAD_HYBRID_PRIVATE_KEY;

    public int ERROR_BAD_ASN1_ALGORITHM;

    public int ERROR_BAD_ASN1_ALGORITHM_ECC;

    public int ERROR_BAD_ASN1_ALGORITHM_COMPOUND_KEY;

    public int ERROR_BAD_ASN1_ALGORITHM_HYBRID_KEY;

    public int ERROR_NO_MESSAGE_INFO;

    public int ERROR_BAD_MESSAGE_INFO;

    public int ERROR_KEY_RECIPIENT_IS_NOT_FOUND;

    public int ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG;

    public int ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG;

    public int ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND;

    public int ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH;

    public int ERROR_BAD_SIGNATURE;

    public int ERROR_BAD_MESSAGE_INFO_FOOTER;

    public int ERROR_INVALID_BRAINKEY_PASSWORD_LEN;

    public int ERROR_INVALID_BRAINKEY_FACTOR_LEN;

    public int ERROR_INVALID_BRAINKEY_POINT_LEN;

    public int ERROR_INVALID_BRAINKEY_KEY_NAME_LEN;

    public int ERROR_BRAINKEY_INTERNAL;

    public int ERROR_BRAINKEY_INVALID_POINT;

    public int ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN;

    public int ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN;

    public int ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN;

    public int ERROR_INVALID_IDENTITY_SECRET;

    public int ERROR_INVALID_KEM_ENCAPSULATED_KEY;

    public int ERROR_INVALID_PADDING;

    public int ERROR_PROTOBUF;

    public int ERROR_SESSION_ID_DOESNT_MATCH;

    public int ERROR_EPOCH_NOT_FOUND;

    public int ERROR_WRONG_KEY_TYPE;

    public int ERROR_INVALID_SIGNATURE;

    public int ERROR_ED25519;

    public int ERROR_DUPLICATE_EPOCH;

    public int ERROR_PLAIN_TEXT_TOO_LONG;

    private int statusCode;

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
        case ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM:
            return "Key algorithm does not accept given type of public key.";
        case ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM:
            return "Key algorithm does not accept given type of private key.";
        case ERROR_BAD_FALCON_PUBLIC_KEY:
            return "Post-quantum Falcon-Sign public key is corrupted.";
        case ERROR_BAD_FALCON_PRIVATE_KEY:
            return "Post-quantum Falcon-Sign private key is corrupted.";
        case ERROR_ROUND5:
            return "Generic Round5 library error.";
        case ERROR_BAD_ROUND5_PUBLIC_KEY:
            return "Post-quantum NIST Round5 public key is corrupted.";
        case ERROR_BAD_ROUND5_PRIVATE_KEY:
            return "Post-quantum NIST Round5 private key is corrupted.";
        case ERROR_BAD_COMPOUND_PUBLIC_KEY:
            return "Compound public key is corrupted.";
        case ERROR_BAD_COMPOUND_PRIVATE_KEY:
            return "Compound private key is corrupted.";
        case ERROR_BAD_HYBRID_PUBLIC_KEY:
            return "Compound public hybrid key is corrupted.";
        case ERROR_BAD_HYBRID_PRIVATE_KEY:
            return "Compound private hybrid key is corrupted.";
        case ERROR_BAD_ASN1_ALGORITHM:
            return "ASN.1 AlgorithmIdentifer is corrupted.";
        case ERROR_BAD_ASN1_ALGORITHM_ECC:
            return "ASN.1 AlgorithmIdentifer with ECParameters is corrupted.";
        case ERROR_BAD_ASN1_ALGORITHM_COMPOUND_KEY:
            return "ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.";
        case ERROR_BAD_ASN1_ALGORITHM_HYBRID_KEY:
            return "ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.";
        case ERROR_NO_MESSAGE_INFO:
            return "Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.";
        case ERROR_BAD_MESSAGE_INFO:
            return "Message Info is corrupted.";
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
        case ERROR_BAD_MESSAGE_INFO_FOOTER:
            return "Message Info footer is corrupted.";
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
        case ERROR_INVALID_KEM_ENCAPSULATED_KEY:
            return "KEM encapsulated key is invalid or does not correspond to the private key.";
        case ERROR_INVALID_PADDING:
            return "Invalid padding.";
        case ERROR_PROTOBUF:
            return "Protobuf error.";
        case ERROR_SESSION_ID_DOESNT_MATCH:
            return "Session id doesnt match.";
        case ERROR_EPOCH_NOT_FOUND:
            return "Epoch not found.";
        case ERROR_WRONG_KEY_TYPE:
            return "Wrong key type.";
        case ERROR_INVALID_SIGNATURE:
            return "Invalid signature.";
        case ERROR_ED25519:
            return "Ed25519 error.";
        case ERROR_DUPLICATE_EPOCH:
            return "Duplicate epoch.";
        case ERROR_PLAIN_TEXT_TOO_LONG:
            return "Plain text too long.";
        default:
            return "Unknown error";
        }
    }

}
