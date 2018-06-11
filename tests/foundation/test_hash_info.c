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


#include "unity.h"

#include "vsf_hash_info.h"
#include "vsf_hash_info_api.h"
#include "vsf_sha256.h"

// --------------------------------------------------------------------------
//  Over implementation: 'sha256'.
// --------------------------------------------------------------------------

void
test__digest_size__sha256__returns_32(void) {
    TEST_ASSERT_EQUAL(32, vsf_hash_info_digest_size(vsf_sha256_hash_info_api()));
}

void
test__api__sha256__returns_not_null(void) {
    TEST_ASSERT_NOT_NULL(vsf_sha256_hash_info_api());
}

void
test__api_tag__sha256__equals_api_tag_HASH_INFO(void) {
    TEST_ASSERT_EQUAL(vsf_api_tag_HASH_INFO, vsf_sha256_hash_info_api()->api_tag);
}


// --------------------------------------------------------------------------
//  Entrypoint
// --------------------------------------------------------------------------

int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__digest_size__sha256__returns_32);
    RUN_TEST(test__api__sha256__returns_not_null);
    RUN_TEST(test__api_tag__sha256__equals_api_tag_HASH_INFO);

    return UNITY_END();
}
