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


#include "benchmark/benchmark.h"

#include "vscf_memory.h"
#include "vscf_random_padding.h"
#include "vscf_padding_cipher.h"
#include "vscf_aes256_gcm.h"
#include "vscf_fake_random.h"
#include "vscf_padding_params.h"

#include "benchmark_data.h"

void
encrypt__1kb_chunked_manualy_by_32_bytes_with_aes256_gcm__success(benchmark::State &state) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_encrypted_len(aes256_gcm, test_data_padding_cipher_PLAINTEXT_1024_ZERO_BYTES.len));


    vscf_aes256_gcm_set_key(aes256_gcm, test_data_padding_cipher_SUITE1_AES256_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_data_padding_cipher_SUITE1_AES256_NONCE);


    for (auto _ : state) {

        for (int i = 0; i < test_data_padding_cipher_PLAINTEXT_1024_ZERO_BYTES.len; i += 32) {

            vscf_aes256_gcm_encrypt(
                    aes256_gcm, vsc_data_slice_beg(test_data_padding_cipher_PLAINTEXT_1024_ZERO_BYTES, i, 32), out);
            vsc_buffer_reset(out);
        }
    }
    vscf_aes256_gcm_destroy(&aes256_gcm);
    vsc_buffer_destroy(&out);
}

void
decrypt__encrypted_1kb_chunked_manualy_by_32_bytes_with_aes256_gcm__success(benchmark::State &state) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_decrypted_len(aes256_gcm, test_data_padding_cipher_ENCRYPTED_1024_ZERO_BYTES.len));


    vscf_aes256_gcm_set_key(aes256_gcm, test_data_padding_cipher_SUITE1_AES256_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_data_padding_cipher_SUITE1_AES256_NONCE);


    for (auto _ : state) {
        // length of enc message is 1040 so it's not fully encrypted that's why i + 32
        for (int i = 0; i + 32 < test_data_padding_cipher_ENCRYPTED_1024_ZERO_BYTES.len; i += 32) {


            vscf_aes256_gcm_decrypt(
                    aes256_gcm, vsc_data_slice_beg(test_data_padding_cipher_ENCRYPTED_1024_ZERO_BYTES, i, 32), out);
            vsc_buffer_reset(out);
        }
    }

    vscf_aes256_gcm_destroy(&aes256_gcm);
    vsc_buffer_destroy(&out);
}

static void
inner_test__encrypt__match_given(vscf_padding_cipher_t *cipher, vsc_data_t plaintext, vsc_data_t ciphertext) {
    //
    //  Encrypt.
    //
    vscf_padding_cipher_start_encryption(cipher);
    const size_t out_len = vscf_padding_cipher_out_len(cipher, plaintext.len) + vscf_padding_cipher_out_len(cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    vscf_padding_cipher_update(cipher, plaintext, out);
    const vscf_status_t status = vscf_padding_cipher_finish(cipher, out);

    //
    //  Cleanup.
    //
    vsc_buffer_reset(out);
}
// --------------------------------------------------------------------------
//  Suite 1: AES256-GCM, frame 160.
// --------------------------------------------------------------------------
static void
inner_test__encrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
        benchmark::State &state, vsc_data_t plaintext, vsc_data_t ciphertext) {

    //
    // Configure algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_random_padding_t *padding = vscf_random_padding_new();
    vscf_random_padding_take_random(padding, vscf_fake_random_impl(fake_random));

    vscf_random_padding_configure(padding, vscf_padding_params_new_with_constraints(32, 32, 32));

    vscf_aes256_gcm_t *cipher = vscf_aes256_gcm_new();
    vscf_aes256_gcm_set_nonce(cipher, test_data_padding_cipher_SUITE1_AES256_NONCE);
    vscf_aes256_gcm_set_key(cipher, test_data_padding_cipher_SUITE1_AES256_KEY);

    vscf_padding_cipher_t *padding_cipher = vscf_padding_cipher_new();
    vscf_padding_cipher_take_padding(padding_cipher, vscf_random_padding_impl(padding));
    vscf_padding_cipher_take_cipher(padding_cipher, vscf_aes256_gcm_impl(cipher));

    //
    // Check.
    //

    for (auto _ : state) {
        inner_test__encrypt__match_given(padding_cipher, plaintext, ciphertext);
    }

    //
    // Cleanup.
    //
    vscf_padding_cipher_destroy(&padding_cipher);
}

void
encrypt__1kb_chunked_with_pading_cipher_by_32_bytes_aes256_gcm__success(benchmark::State &state) {
    inner_test__encrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(state,
            test_data_padding_cipher_PLAINTEXT_1024_ZERO_BYTES, test_data_padding_cipher_ENCRYPTED_1024_ZERO_BYTES);
}


static void
inner_test__decrypt__match_given(vscf_padding_cipher_t *cipher, vsc_data_t ciphertext, vsc_data_t plaintext) {
    //
    //  Decrypt.
    //
    vscf_padding_cipher_start_decryption(cipher);
    const size_t out_len = vscf_padding_cipher_out_len(cipher, ciphertext.len) + vscf_padding_cipher_out_len(cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    vscf_padding_cipher_update(cipher, ciphertext, out);
    const vscf_status_t status = vscf_padding_cipher_finish(cipher, out);

    vsc_buffer_reset(out);
}

static void
inner_test__decrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
        benchmark::State &state, vsc_data_t ciphertext, vsc_data_t plaintext) {

    //
    // Configure algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_random_padding_t *padding = vscf_random_padding_new();
    vscf_random_padding_take_random(padding, vscf_fake_random_impl(fake_random));

    vscf_random_padding_configure(padding, vscf_padding_params_new_with_constraints(32, 32, 32));


    vscf_aes256_gcm_t *cipher = vscf_aes256_gcm_new();
    vscf_aes256_gcm_set_nonce(cipher, test_data_padding_cipher_SUITE1_AES256_NONCE);
    vscf_aes256_gcm_set_key(cipher, test_data_padding_cipher_SUITE1_AES256_KEY);

    vscf_padding_cipher_t *padding_cipher = vscf_padding_cipher_new();
    vscf_padding_cipher_take_padding(padding_cipher, vscf_random_padding_impl(padding));
    vscf_padding_cipher_take_cipher(padding_cipher, vscf_aes256_gcm_impl(cipher));

    //
    // Check.
    //
    for (auto _ : state) {
        inner_test__decrypt__match_given(padding_cipher, ciphertext, plaintext);
    }

    //
    // Cleanup.
    //
    vscf_padding_cipher_destroy(&padding_cipher);
}

void
decrypt___encrypted_1kb_chunked_with_pading_cipher_by_32_bytes_aes256_gcm__success(benchmark::State &state) {

    inner_test__decrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(state,
            test_data_padding_cipher_ENCRYPTED_WITH_PADDING_1024_ZERO_BYTES,
            test_data_padding_cipher_PLAINTEXT_1024_ZERO_BYTES);
}


BENCHMARK(encrypt__1kb_chunked_manualy_by_32_bytes_with_aes256_gcm__success);
BENCHMARK(decrypt__encrypted_1kb_chunked_manualy_by_32_bytes_with_aes256_gcm__success);

BENCHMARK(encrypt__1kb_chunked_with_pading_cipher_by_32_bytes_aes256_gcm__success);
BENCHMARK(decrypt___encrypted_1kb_chunked_with_pading_cipher_by_32_bytes_aes256_gcm__success);
