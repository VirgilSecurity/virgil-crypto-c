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

#include "vscf_sha512.h"

#include "benchmark_data.h"

#include "vscf_recipient_cipher.h"
#include "vscf_key_provider.h"


static void
benchmark__encrypt__for_1_key_recipient(benchmark::State &state) {

    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    VSCF_UNUSED(vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(
            key_provider, benchmark_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, benchmark_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    //
    //  Encrypt.
    //
    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(512);

    for (auto _ : state) {
        VSCF_UNUSED(vscf_recipient_cipher_start_encryption(recipient_cipher));
        vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);
        VSCF_UNUSED(vscf_recipient_cipher_process_encryption(
                recipient_cipher, benchmark_data_recipient_cipher_MESSAGE, enc_msg));
        VSCF_UNUSED(vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));
        vsc_buffer_reset(enc_msg);
    }

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
benchmark__encrypt__for_30_key_recipients(benchmark::State &state) {

    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    VSCF_UNUSED(vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(
            key_provider, benchmark_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    for (size_t i = 0; i < 30; ++i) { // change recipient id, key is the same
        auto id = vsc_data((byte *)&i, sizeof(i));
        vscf_recipient_cipher_add_key_recipient(recipient_cipher, id, public_key);
    }

    //
    //  Encrypt.
    //
    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(11000);

    for (auto _ : state) {
        VSCF_UNUSED(vscf_recipient_cipher_start_encryption(recipient_cipher));
        vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);
        VSCF_UNUSED(vscf_recipient_cipher_process_encryption(
                recipient_cipher, benchmark_data_recipient_cipher_MESSAGE, enc_msg));
        VSCF_UNUSED(vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));
        vsc_buffer_reset(enc_msg);
    }

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
benchmark__decrypt__for_key_recipient(benchmark::State &state) {
    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    VSCF_UNUSED(vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(
            key_provider, benchmark_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(
            key_provider, benchmark_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, benchmark_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    //
    //  Encrypt.
    //
    VSCF_UNUSED(vscf_recipient_cipher_start_encryption(recipient_cipher));

    size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
    size_t enc_msg_len =
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, benchmark_data_recipient_cipher_MESSAGE.len) +
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(message_info_len + enc_msg_len);

    vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);

    VSCF_UNUSED(vscf_recipient_cipher_process_encryption(
            recipient_cipher, benchmark_data_recipient_cipher_MESSAGE, enc_msg));
    VSCF_UNUSED(vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));

    //
    //  Clear and decrypt.
    //
    vscf_recipient_cipher_release_random(recipient_cipher);
    vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(1100);
    for (auto _ : state) {
        VSCF_UNUSED(vscf_recipient_cipher_start_decryption_with_key(
                recipient_cipher, benchmark_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

        VSCF_UNUSED(vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg), dec_msg));
        VSCF_UNUSED(vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

        vsc_buffer_reset(dec_msg);
    }

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&dec_msg);
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

BENCHMARK(benchmark__encrypt__for_1_key_recipient);
BENCHMARK(benchmark__encrypt__for_30_key_recipients);

BENCHMARK(benchmark__decrypt__for_key_recipient);
