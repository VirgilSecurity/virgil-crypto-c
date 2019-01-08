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


#include "test_data_base64.h"


//
//  Test vectors from RFC 4648
//
//
//  BASE64("") = ""
//
const vsc_data_t test_base64_DECODED_EMPTY = {(const byte *)0xDEADBEAF, 0};

const vsc_data_t test_base64_ENCODED_EMPTY = {(const byte *)0xDEADBEAF, 0};

//
//  BASE64("f") = "Zg=="
//
const byte test_base64_DECODED_LOWERCASE_F_BYTES[] = {
    0x66
};

const vsc_data_t test_base64_DECODED_LOWERCASE_F = {
    test_base64_DECODED_LOWERCASE_F_BYTES, sizeof(test_base64_DECODED_LOWERCASE_F_BYTES)
};

const byte test_base64_ENCODED_LOWERCASE_F_BYTES[] = {
     0x5A, 0x67, 0x3D, 0x3D
};

const vsc_data_t test_base64_ENCODED_LOWERCASE_F = {
    test_base64_ENCODED_LOWERCASE_F_BYTES, sizeof(test_base64_ENCODED_LOWERCASE_F_BYTES)
};

//
//  BASE64("fo") = "Zm8="
//
const byte test_base64_DECODED_LOWERCASE_FO_BYTES[] = {
    0x66, 0x6F
};

const vsc_data_t test_base64_DECODED_LOWERCASE_FO = {
    test_base64_DECODED_LOWERCASE_FO_BYTES, sizeof(test_base64_DECODED_LOWERCASE_FO_BYTES)
};

const byte test_base64_ENCODED_LOWERCASE_FO_BYTES[] = {
    0x5A, 0x6D, 0x38, 0x3D
};

const vsc_data_t test_base64_ENCODED_LOWERCASE_FO = {
    test_base64_ENCODED_LOWERCASE_FO_BYTES, sizeof(test_base64_ENCODED_LOWERCASE_FO_BYTES)
};

//
//  BASE64("foo") = "Zm9v"
//
const byte test_base64_DECODED_LOWERCASE_FOO_BYTES[] = {
    0x66, 0x6F, 0x6F
};

const vsc_data_t test_base64_DECODED_LOWERCASE_FOO = {
    test_base64_DECODED_LOWERCASE_FOO_BYTES, sizeof(test_base64_DECODED_LOWERCASE_FOO_BYTES)
};

const byte test_base64_ENCODED_LOWERCASE_FOO_BYTES[] = {
     0x5A, 0x6D, 0x39, 0x76
};

const vsc_data_t test_base64_ENCODED_LOWERCASE_FOO = {
    test_base64_ENCODED_LOWERCASE_FOO_BYTES, sizeof(test_base64_ENCODED_LOWERCASE_FOO_BYTES)
};

//
//  BASE64("foob") = "Zm9vYg=="
//
const byte test_base64_DECODED_LOWERCASE_FOOB_BYTES[] = {
    0x66, 0x6F, 0x6F, 0x62
};

const vsc_data_t test_base64_DECODED_LOWERCASE_FOOB = {
    test_base64_DECODED_LOWERCASE_FOOB_BYTES, sizeof(test_base64_DECODED_LOWERCASE_FOOB_BYTES)
};

const byte test_base64_ENCODED_LOWERCASE_FOOB_BYTES[] = {
    0x5A, 0x6D, 0x39, 0x76, 0x59, 0x67, 0x3D, 0x3D
};

const vsc_data_t test_base64_ENCODED_LOWERCASE_FOOB = {
    test_base64_ENCODED_LOWERCASE_FOOB_BYTES, sizeof(test_base64_ENCODED_LOWERCASE_FOOB_BYTES)
};

//
//  BASE64("fooba") = "Zm9vYmE="
//
const byte test_base64_DECODED_LOWERCASE_FOOBA_BYTES[] = {
    0x66, 0x6F, 0x6F, 0x62, 0x61
};

const vsc_data_t test_base64_DECODED_LOWERCASE_FOOBA = {
    test_base64_DECODED_LOWERCASE_FOOBA_BYTES, sizeof(test_base64_DECODED_LOWERCASE_FOOBA_BYTES)
};

const byte test_base64_ENCODED_LOWERCASE_FOOBA_BYTES[] = {
    0x5A, 0x6D, 0x39, 0x76, 0x59, 0x6D, 0x45, 0x3D
};

const vsc_data_t test_base64_ENCODED_LOWERCASE_FOOBA = {
    test_base64_ENCODED_LOWERCASE_FOOBA_BYTES, sizeof(test_base64_ENCODED_LOWERCASE_FOOBA_BYTES)
};

//
//  BASE64("foobar") = "Zm9vYmFy"
//
const byte test_base64_DECODED_LOWERCASE_FOOBAR_BYTES[] = {
    0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72
};

const vsc_data_t test_base64_DECODED_LOWERCASE_FOOBAR = {
    test_base64_DECODED_LOWERCASE_FOOBAR_BYTES, sizeof(test_base64_DECODED_LOWERCASE_FOOBAR_BYTES)
};

const byte test_base64_ENCODED_LOWERCASE_FOOBAR_BYTES[] = {
    0x5A, 0x6D, 0x39, 0x76, 0x59, 0x6D, 0x46, 0x79
};

const vsc_data_t test_base64_ENCODED_LOWERCASE_FOOBAR = {
    test_base64_ENCODED_LOWERCASE_FOOBAR_BYTES, sizeof(test_base64_ENCODED_LOWERCASE_FOOBAR_BYTES)
};
