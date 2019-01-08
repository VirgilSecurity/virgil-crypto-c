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


#include "test_data_sha224.h"

//
//  Test Vector 1
//
const vsc_data_t test_sha224_VECTOR_1_INPUT = {(const byte *)0xDEADBEAF, 0};

const byte test_sha224_VECTOR_1_DIGEST_BYTES[] = {
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
    0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
    0xc5, 0xb3, 0xe4, 0x2f,
};

const vsc_data_t test_sha224_VECTOR_1_DIGEST = {
    test_sha224_VECTOR_1_DIGEST_BYTES, sizeof(test_sha224_VECTOR_1_DIGEST_BYTES)
};


//
//  Test Vector 2
//
const byte test_sha224_VECTOR_2_INPUT_BYTES[] = { 0x84 };

const vsc_data_t test_sha224_VECTOR_2_INPUT = {
    test_sha224_VECTOR_2_INPUT_BYTES, sizeof(test_sha224_VECTOR_2_INPUT_BYTES)
};

const byte test_sha224_VECTOR_2_DIGEST_BYTES[] = {
    0x3c, 0xd3, 0x69, 0x21, 0xdf, 0x5d, 0x69, 0x63,
    0xe7, 0x37, 0x39, 0xcf, 0x4d, 0x20, 0x21, 0x1e,
    0x2d, 0x88, 0x77, 0xc1, 0x9c, 0xff, 0x08, 0x7a,
    0xde, 0x9d, 0x0e, 0x3a,
};

const vsc_data_t test_sha224_VECTOR_2_DIGEST = {
    test_sha224_VECTOR_2_DIGEST_BYTES, sizeof(test_sha224_VECTOR_2_DIGEST_BYTES)
};


//
//  Test Vector 3
//
const byte test_sha224_VECTOR_3_INPUT_BYTES[] = { 0x5c, 0x7b };

const vsc_data_t test_sha224_VECTOR_3_INPUT = {
    test_sha224_VECTOR_3_INPUT_BYTES, sizeof(test_sha224_VECTOR_3_INPUT_BYTES)
};

const byte test_sha224_VECTOR_3_DIGEST_BYTES[] = {
    0xda, 0xff, 0x9b, 0xce, 0x68, 0x5e, 0xb8, 0x31,
    0xf9, 0x7f, 0xc1, 0x22, 0x5b, 0x03, 0xc2, 0x75,
    0xa6, 0xc1, 0x12, 0xe2, 0xd6, 0xe7, 0x6f, 0x5f,
    0xaf, 0x7a, 0x36, 0xe6,
};

const vsc_data_t test_sha224_VECTOR_3_DIGEST = {
    test_sha224_VECTOR_3_DIGEST_BYTES, sizeof(test_sha224_VECTOR_3_DIGEST_BYTES)
};

