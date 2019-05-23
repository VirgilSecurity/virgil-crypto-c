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

#include <virgil/crypto/foundation/vscf_assert.h>
#include "unity.h"
#include "test_utils.h"
#include "setjmp.h"


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_RECIPIENT_CIPHER && VSCF_ALG_FACTORY && VSCF_KEY_ASN1_DESERIALIZER && VSCF_SECP256R1_PUBLIC_KEY &&           \
            VSCF_SECP256R1_PRIVATE_KEY)

#include "vscf_key_asn1_deserializer.h"
#include "vscf_alg_factory.h"
#include "vscf_recipient_cipher.h"
#include "vscf_secp256r1_private_key.h"
#include "vscf_fake_random.h"

#include "test_data_recipient_cipher.h"

#include "vsc_assert.h"

static jmp_buf buf;

void fuzz_assert_handler(const char *message, const char *file, int line)
{
    printf("%s %d", message, line);
    longjmp(buf, 1);
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    vscf_assert_change_handler(fuzz_assert_handler);
    vsc_assert_change_handler(fuzz_assert_handler);

    int res = setjmp(buf);

    if (size < 76) {
        return 0;
    }

    if (res != 0)
    {
        return 0;
    }

    //
    //  Prepare decryption key.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vsc_data_t fuzz_data = vsc_data(data, size);

    //
    //  Configure dependencies.
    //
    vscf_fake_random_t *nonce_rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(nonce_rng, vsc_data_slice_beg(fuzz_data, 64, 12));

    vscf_secp256r1_private_key_t *ephemeral_key = vscf_secp256r1_private_key_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_secp256r1_private_key_import_private_key(ephemeral_key, vsc_data_slice_beg(fuzz_data, 32, 32)));

    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_take_random(ecies, vscf_fake_random_impl(nonce_rng));
    vscf_ecies_take_ephemeral_key(ecies, vscf_secp256r1_private_key_impl(ephemeral_key));

    vscf_secp256r1_private_key_t *private_key = vscf_secp256r1_private_key_new();
    vscf_secp256r1_private_key_take_ecies(private_key, ecies);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_secp256r1_private_key_import_private_key(private_key, vsc_data_slice_beg(fuzz_data, 0, 32)));

    vscf_impl_t *public_key = vscf_secp256r1_private_key_extract_public_key(private_key);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(recipient_cipher, vsc_data_from_str("key", 3), public_key);

    vscf_fake_random_t *nonce_rng2 = vscf_fake_random_new();
    vscf_recipient_cipher_take_random(recipient_cipher, vscf_fake_random_impl(nonce_rng2));

    vsc_data_t plain_data = vsc_data_from_str("test", 4);

    //TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(recipient_cipher));

    if (vscf_recipient_cipher_start_encryption(recipient_cipher) != vscf_status_SUCCESS)
    {
        return 0;
    }

    size_t enc_buf_capacity = vscf_recipient_cipher_encryption_out_len(recipient_cipher, plain_data.len) +
                              vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);
    vsc_buffer_t *enc_buf = vsc_buffer_new_with_capacity(enc_buf_capacity);


    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_process_encryption(recipient_cipher, plain_data, enc_buf));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_buf));

    //
    //  Cleanup.
    //
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_secp256r1_private_key_destroy(&private_key);
    vsc_buffer_destroy(&enc_buf);
    return 0;
}
