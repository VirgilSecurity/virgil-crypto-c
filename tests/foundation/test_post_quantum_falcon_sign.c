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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCF_POST_QUANTUM
#if TEST_DEPENDENCIES_AVAILABLE

#include <falcon/falcon.h>

enum { LOGN_512 = 9, LOGN_1024 = 10 };

// clang-format off
static const unsigned char k_rng_seed[] = {
  0x3d, 0x38, 0xc7, 0x72, 0x70, 0xff, 0xbf, 0x82, 0xaa, 0x1d, 0x0d, 0x84,
  0xa3, 0x4f, 0xb0, 0x17, 0x3a, 0x3a, 0x56, 0x5c, 0x42, 0x56, 0xb7, 0x93,
  0x5e, 0x95, 0x4e, 0x01, 0x3d, 0x15, 0x60, 0xa3, 0x85, 0x4c, 0x2f, 0xe3,
  0xf2, 0xa6, 0xd9, 0x2a, 0x1e, 0x15, 0xbb, 0x84, 0xb5, 0xf8, 0x1d, 0x9f
};
// clang-format on

void
test__keygen__512_degree__success(void) {
    unsigned char privkey[FALCON_PRIVKEY_SIZE(LOGN_512)] = {0x00};
    unsigned char pubkey[FALCON_PUBKEY_SIZE(LOGN_512)] = {0x00};
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(LOGN_512)] = {0x00};

    shake256_context shake256;
    shake256_init(&shake256);
    shake256_inject(&shake256, k_rng_seed, sizeof(k_rng_seed));
    shake256_flip(&shake256);

    int status =
            falcon_keygen_make(&shake256, LOGN_512, privkey, sizeof(privkey), pubkey, sizeof(pubkey), tmp, sizeof(tmp));
    TEST_ASSERT_EQUAL(0, status);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__keygen__512_degree__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
