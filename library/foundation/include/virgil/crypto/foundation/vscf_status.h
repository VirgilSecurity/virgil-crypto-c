//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Defines the library status codes.
// --------------------------------------------------------------------------

#ifndef VSCF_STATUS_H_INCLUDED
#define VSCF_STATUS_H_INCLUDED

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Defines the library status codes.
//
enum vscf_status_t {
    //
    //  No errors was occurred.
    //
    vscf_status_SUCCESS = 0,
    //
    //  This error should not be returned if assertions is enabled.
    //
    vscf_status_ERROR_BAD_ARGUMENTS = -1,
    //
    //  Can be used to define that not all context prerequisites are satisfied.
    //  Note, this error should not be returned if assertions is enabled.
    //
    vscf_status_ERROR_UNINITIALIZED = -2,
    //
    //  Define that error code from one of third-party module was not handled.
    //  Note, this error should not be returned if assertions is enabled.
    //
    vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR = -3,
    //
    //  Buffer capacity is not enough to hold result.
    //
    vscf_status_ERROR_SMALL_BUFFER = -101,
    //
    //  Unsupported algorithm.
    //
    vscf_status_ERROR_UNSUPPORTED_ALGORITHM = -200,
    //
    //  Authentication failed during decryption.
    //
    vscf_status_ERROR_AUTH_FAILED = -201,
    //
    //  Attempt to read data out of buffer bounds.
    //
    vscf_status_ERROR_OUT_OF_DATA = -202,
    //
    //  ASN.1 encoded data is corrupted.
    //
    vscf_status_ERROR_BAD_ASN1 = -203,
    //
    //  Attempt to read ASN.1 type that is bigger then requested C type.
    //
    vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING = -204,
    //
    //  ASN.1 representation of PKCS#1 public key is corrupted.
    //
    vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY = -205,
    //
    //  ASN.1 representation of PKCS#1 private key is corrupted.
    //
    vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY = -206,
    //
    //  ASN.1 representation of PKCS#8 public key is corrupted.
    //
    vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY = -207,
    //
    //  ASN.1 representation of PKCS#8 private key is corrupted.
    //
    vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY = -208,
    //
    //  Encrypted data is corrupted.
    //
    vscf_status_ERROR_BAD_ENCRYPTED_DATA = -209,
    //
    //  Underlying random operation returns error.
    //
    vscf_status_ERROR_RANDOM_FAILED = -210,
    //
    //  Generation of the private or secret key failed.
    //
    vscf_status_ERROR_KEY_GENERATION_FAILED = -211,
    //
    //  One of the entropy sources failed.
    //
    vscf_status_ERROR_ENTROPY_SOURCE_FAILED = -212,
    //
    //  Requested data to be generated is too big.
    //
    vscf_status_ERROR_RNG_REQUESTED_DATA_TOO_BIG = -213,
    //
    //  Base64 encoded string contains invalid characters.
    //
    vscf_status_ERROR_BAD_BASE64 = -214,
    //
    //  PEM data is corrupted.
    //
    vscf_status_ERROR_BAD_PEM = -215,
    //
    //  Exchange key return zero.
    //
    vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED = -216,
    //
    //  Ed25519 public key is corrupted.
    //
    vscf_status_ERROR_BAD_ED25519_PUBLIC_KEY = -217,
    //
    //  Ed25519 private key is corrupted.
    //
    vscf_status_ERROR_BAD_ED25519_PRIVATE_KEY = -218,
    //
    //  CURVE25519 public key is corrupted.
    //
    vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY = -219,
    //
    //  CURVE25519 private key is corrupted.
    //
    vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY = -220,
    //
    //  Decryption failed, because message info was not given explicitly,
    //  and was not part of an encrypted message.
    //
    vscf_status_ERROR_NO_MESSAGE_INFO = -301,
    //
    //  Message info is corrupted.
    //
    vscf_status_ERROR_BAD_MESSAGE_INFO = -302,
    //
    //  Recipient defined with id is not found within message info
    //  during data decryption.
    //
    vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND = -303,
    //
    //  Content encryption key can not be decrypted with a given private key.
    //
    vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG = -304,
    //
    //  Content encryption key can not be decrypted with a given password.
    //
    vscf_status_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG = -305,
    //
    //  Custom parameter with a given key is not found within message info.
    //
    vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND = -306,
    //
    //  A custom parameter with a given key is found, but the requested value
    //  type does not correspond to the actual type.
    //
    vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH = -307,
    //
    //  Signature format is corrupted.
    //
    vscf_status_ERROR_BAD_SIGNATURE = -308,
    //
    //  Operation on HSM failed.
    //
    vscf_status_ERROR_HSM_FAILED = -401
};
typedef enum vscf_status_t vscf_status_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_STATUS_H_INCLUDED
//  @end
