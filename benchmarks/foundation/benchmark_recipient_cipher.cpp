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

#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_recipient_cipher.h"

#include "benchmark_data.h"


constexpr const char k_recipient_id_str[] = "2e8176ba-34db-4c65-b977-c5eac687c4ac";
const vsc_data_t k_recipient_id = vsc_data_from_str(k_recipient_id_str, sizeof(k_recipient_id_str) - 1);

constexpr const char k_data_str[] = "this string will be encrypted";
const vsc_data_t k_data = vsc_data_from_str(k_data_str, sizeof(k_data_str) - 1);

constexpr const size_t k_enc_len_max = 2048;


static void
recipient_cipher_encrypt(benchmark::State &state) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    (void)vscf_key_provider_setup_defaults(key_provider);

    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);
    if (alg_id == vscf_alg_id_RSA) {
        const size_t bitlen = (size_t)state.range(1);
        vscf_key_provider_set_rsa_params(key_provider, bitlen);
    }

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vscf_recipient_cipher_t *cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(cipher, k_recipient_id, public_key);

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(k_enc_len_max);
    for (auto _ : state) {
        (void)vscf_recipient_cipher_start_encryption(cipher);
        (void)vscf_recipient_cipher_pack_message_info(cipher, enc);
        (void)vscf_recipient_cipher_process_encryption(cipher, k_data, enc);
        (void)vscf_recipient_cipher_finish_encryption(cipher, enc);
        vsc_buffer_reset(enc);
    }

    vsc_buffer_destroy(&enc);
    vscf_recipient_cipher_destroy(&cipher);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


static void
recipient_cipher_decrypt(benchmark::State &state) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    (void)vscf_key_provider_setup_defaults(key_provider);

    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);
    if (alg_id == vscf_alg_id_RSA) {
        const size_t bitlen = (size_t)state.range(1);
        vscf_key_provider_set_rsa_params(key_provider, bitlen);
    }

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vscf_recipient_cipher_t *cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(cipher, k_recipient_id, public_key);
    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(k_enc_len_max);
    vsc_buffer_t *plain = vsc_buffer_new_with_capacity(k_enc_len_max);

    (void)vscf_recipient_cipher_start_encryption(cipher);
    (void)vscf_recipient_cipher_pack_message_info(cipher, enc);
    (void)vscf_recipient_cipher_process_encryption(cipher, k_data, enc);
    (void)vscf_recipient_cipher_finish_encryption(cipher, enc);

    vsc_data_t enc_data = vsc_buffer_data(enc);
    for (auto _ : state) {
        (void)vscf_recipient_cipher_start_decryption_with_key(cipher, k_recipient_id, private_key, vsc_data_empty());
        (void)vscf_recipient_cipher_process_decryption(cipher, enc_data, plain);
        (void)vscf_recipient_cipher_finish_decryption(cipher, plain);
        vsc_buffer_reset(plain);
    }

    vsc_buffer_destroy(&plain);
    vsc_buffer_destroy(&enc);
    vscf_recipient_cipher_destroy(&cipher);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


BENCHMARK(recipient_cipher_encrypt)->ArgNames({"Ed25519"})->Arg(vscf_alg_id_ED25519);
BENCHMARK(recipient_cipher_encrypt)->ArgNames({"Curve25519"})->Arg(vscf_alg_id_CURVE25519);
BENCHMARK(recipient_cipher_encrypt)->ArgNames({"secp256r1"})->Arg(vscf_alg_id_SECP256R1);
BENCHMARK(recipient_cipher_encrypt)->ArgNames({"RSA"})->Args({vscf_alg_id_RSA, 4096});

BENCHMARK(recipient_cipher_decrypt)->ArgNames({"Ed25519"})->Arg(vscf_alg_id_ED25519);
BENCHMARK(recipient_cipher_decrypt)->ArgNames({"Curve25519"})->Arg(vscf_alg_id_CURVE25519);
BENCHMARK(recipient_cipher_decrypt)->ArgNames({"secp256r1"})->Arg(vscf_alg_id_SECP256R1);
BENCHMARK(recipient_cipher_decrypt)->ArgNames({"RSA"})->Args({vscf_alg_id_RSA, 4096});
