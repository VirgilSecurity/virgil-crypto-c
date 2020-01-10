//  Copyright (C) 2015-2020 Virgil Security, Inc.
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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE KECCAK_LIBRARY
#if TEST_DEPENDENCIES_AVAILABLE

#include <KeccakHash.h>


void
test__sha3_512__success(void) {
    //
    //  Input
    //
    const BitSequence data[] = {0x4A, 0x4F, 0x20, 0x24, 0x84, 0x51, 0x25, 0x26};
    const size_t data_len = sizeof(data);
    const size_t data_bitlen = 8 * data_len;

    //
    //  Expected Output
    //
    // clang-format off
    const BitSequence digest[] = {
        0x15, 0x0D, 0x78, 0x7D, 0x6E, 0xB4, 0x96, 0x70,
        0xC2, 0xA4, 0xCC, 0xD1, 0x7E, 0x6C, 0xCE, 0x7A,
        0x04, 0xC1, 0xFE, 0x30, 0xFC, 0xE0, 0x3D, 0x1E,
        0xF2, 0x50, 0x17, 0x52, 0xD9, 0x2A, 0xE0, 0x4C,
        0xB3, 0x45, 0xFD, 0x42, 0xE5, 0x10, 0x38, 0xC8,
        0x3B, 0x2B, 0x4F, 0x8F, 0xD4, 0x38, 0xD1, 0xB4,
        0xB5, 0x5C, 0xC5, 0x88, 0xC6, 0xB9, 0x13, 0x13,
        0x2F, 0x1A, 0x65, 0x8F, 0xB1, 0x22, 0xCB, 0x52,
    };
    BitSequence out[sizeof(digest)] = {0x00};
    // clang-format on

    Keccak_HashInstance hash;
    Keccak_HashInitialize_SHA3_512(&hash);
    Keccak_HashUpdate(&hash, data, data_bitlen);
    Keccak_HashFinal(&hash, out);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(digest, out, sizeof(digest));
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__sha3_512__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
