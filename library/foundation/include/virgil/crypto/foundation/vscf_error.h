//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
//  Defines library error codes.
// --------------------------------------------------------------------------

#ifndef VSCF_ERROR_H_INCLUDED
#define VSCF_ERROR_H_INCLUDED

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
//  Defines library error codes.
//
enum vscf_error_t {
    //
    //  No errors was occurred.
    //
    vscf_SUCCESS = 0,
    //
    //  This error should not be returned if assertions is enabled.
    //
    vscf_error_BAD_ARGUMENTS = -1,
    //
    //  Can be used to define that not all context prerequisites are satisfied.
    //  Note, this error should not be returned if assertions is enabled.
    //
    vscf_error_UNINITIALIZED = -2,
    //
    //  Define that error code from one of third-party module was not handled.
    //  Note, this error should not be returned if assertions is enabled.
    //
    vscf_error_UNHANDLED_THIRDPARTY_ERROR = -3,
    //
    //  Buffer capacity is not enaugh to hold result.
    //
    vscf_error_SMALL_BUFFER = -101,
    //
    //  Authentication failed during decryption.
    //
    vscf_error_AUTH_FAILED = -201,
    //
    //  Attempt to read data out of buffer bounds.
    //
    vscf_error_OUT_OF_DATA = -202,
    //
    //  ASN.1 encoded data is corrupted.
    //
    vscf_error_BAD_ASN1 = -203,
    //
    //  Attempt to read ASN.1 type that is bigger then requested C type.
    //
    vscf_error_ASN1_LOSSY_TYPE_NARROWING = -204,
    //
    //  ASN.1 representation of PKCS#1 public key is corrupted.
    //
    vscf_error_BAD_PKCS1_PUBLIC_KEY = -205,
    //
    //  ASN.1 representation of PKCS#1 private key is corrupted.
    //
    vscf_error_BAD_PKCS1_PRIVATE_KEY = -206,
    //
    //  ASN.1 representation of PKCS#8 public key is corrupted.
    //
    vscf_error_BAD_PKCS8_PUBLIC_KEY = -207,
    //
    //  ASN.1 representation of PKCS#8 private key is corrupted.
    //
    vscf_error_BAD_PKCS8_PRIVATE_KEY = -208,
    //
    //  Encrypted data is corrupted.
    //
    vscf_error_BAD_ENCRYPTED_DATA = -209,
    //
    //  Underlying random operation returns error.
    //
    vscf_error_RANDOM_FAILED = -210,
    //
    //  Generation of the private or secret key failed.
    //
    vscf_error_KEY_GENERATION_FAILED = -211,
    //
    //  One of the entropy sources failed.
    //
    vscf_error_ENTROPY_SOURCE_FAILED = -212,
    //
    //  Requested data to be generated is too big.
    //
    vscf_error_RNG_REQUESTED_DATA_TOO_BIG = -213,
    //
    //  Base64 encoded string contains invalid characters.
    //
    vscf_error_BAD_BASE64 = -214,
    //
    //  PEM data is corrupted.
    //
    vscf_error_BAD_PEM = -215
};
typedef enum vscf_error_t vscf_error_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ERROR_H_INCLUDED
//  @end
