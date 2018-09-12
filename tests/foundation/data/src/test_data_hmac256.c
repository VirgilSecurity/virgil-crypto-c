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


#include "test_data_sha256.h"


//
//  Test Vector 1
//
const byte test_hmac256_KEY_1_INPUT_BYTES[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b,
};

const vsc_data_t test_hmac256_KEY_1_INPUT = {
    test_hmac256_KEY_1_INPUT_BYTES, sizeof(test_hmac256_KEY_1_INPUT_BYTES)
};
const byte test_hmac256_VECTOR_1_INPUT_BYTES[] = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };

const vsc_data_t test_hmac256_VECTOR_1_INPUT = {
    test_hmac256_VECTOR_1_INPUT_BYTES, sizeof(test_hmac256_VECTOR_1_INPUT_BYTES)
};

const byte test_hmac256_VECTOR_1_DIGEST_BYTES[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
    0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
};

const vsc_data_t test_hmac256_VECTOR_1_DIGEST = {
    test_hmac256_VECTOR_1_DIGEST_BYTES, sizeof(test_hmac256_VECTOR_1_DIGEST_BYTES)
};


//
//  Test Vector 2
//
const byte test_hmac256_KEY_2_INPUT_BYTES[] = {
    0x4a, 0x65, 0x66, 0x65,
};

const vsc_data_t test_hmac256_KEY_2_INPUT = {
    test_hmac256_KEY_2_INPUT_BYTES, sizeof(test_hmac256_KEY_2_INPUT_BYTES)
};
const byte test_hmac256_VECTOR_2_INPUT_BYTES[] = {
    0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
    0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
    0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
    0x69, 0x6e, 0x67, 0x3f };

const vsc_data_t test_hmac256_VECTOR_2_INPUT = {
    test_hmac256_VECTOR_2_INPUT_BYTES, sizeof(test_hmac256_VECTOR_2_INPUT_BYTES)
};

const byte test_hmac256_VECTOR_2_DIGEST_BYTES[] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
    0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
    0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
};

const vsc_data_t test_hmac256_VECTOR_2_DIGEST = {
    test_hmac256_VECTOR_2_DIGEST_BYTES, sizeof(test_hmac256_VECTOR_2_DIGEST_BYTES)
};


//
//  Test Vector 3
//
const byte test_hmac256_KEY_3_INPUT_BYTES[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
};

const vsc_data_t test_hmac256_KEY_3_INPUT = {
    test_hmac256_KEY_3_INPUT_BYTES, sizeof(test_hmac256_KEY_3_INPUT_BYTES)
};
const byte test_hmac256_VECTOR_3_INPUT_BYTES[] = {
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd,
};

const vsc_data_t test_hmac256_VECTOR_3_INPUT = {
    test_hmac256_VECTOR_3_INPUT_BYTES, sizeof(test_hmac256_VECTOR_3_INPUT_BYTES)
};

const byte test_hmac256_VECTOR_3_DIGEST_BYTES[] = {
    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
    0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
    0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
    0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
};

const vsc_data_t test_hmac256_VECTOR_3_DIGEST = {
    test_hmac256_VECTOR_3_DIGEST_BYTES, sizeof(test_hmac256_VECTOR_3_DIGEST_BYTES)
};


