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


#include "benchmark/benchmark.h"

#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_signer.h"
#include "vscf_verifier.h"
#include "vscf_ctr_drbg.h"
#include "vscf_sha384.h"

#include "benchmark_data.h"


constexpr const char k_data_str[] = "this string will be signed";
const vsc_data_t k_data = vsc_data_from_str(k_data_str, sizeof(k_data_str) - 1);

constexpr const size_t k_signature_len_max = 1024;


static void
signer_sign(benchmark::State &state) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    (void)vscf_ctr_drbg_setup_defaults(ctr_drbg);
    vscf_impl_t *rng = vscf_ctr_drbg_impl(ctr_drbg);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, rng);
    (void)vscf_key_provider_setup_defaults(key_provider);

    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);
    if (alg_id == vscf_alg_id_RSA) {
        const size_t bitlen = (size_t)state.range(1);
        vscf_key_provider_set_rsa_params(key_provider, bitlen);
    }

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_use_random(signer, rng);
    vscf_signer_take_hash(signer, vscf_sha384_impl(vscf_sha384_new()));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(k_signature_len_max);

    for (auto _ : state) {
        vscf_signer_reset(signer);
        vscf_signer_append_data(signer, k_data);
        (void)vscf_signer_sign(signer, private_key, signature);
        vsc_buffer_reset(signature);
    }

    vsc_buffer_destroy(&signature);
    vscf_signer_destroy(&signer);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&rng);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}

static void
verifier_verify(benchmark::State &state) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    (void)vscf_ctr_drbg_setup_defaults(ctr_drbg);
    vscf_impl_t *rng = vscf_ctr_drbg_impl(ctr_drbg);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, rng);
    (void)vscf_key_provider_setup_defaults(key_provider);

    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);
    if (alg_id == vscf_alg_id_RSA) {
        const size_t bitlen = (size_t)state.range(1);
        vscf_key_provider_set_rsa_params(key_provider, bitlen);
    }

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_use_random(signer, rng);
    vscf_signer_take_hash(signer, vscf_sha384_impl(vscf_sha384_new()));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(k_signature_len_max);
    vscf_signer_reset(signer);
    vscf_signer_append_data(signer, k_data);
    (void)vscf_signer_sign(signer, private_key, signature);

    vscf_verifier_t *verifier = vscf_verifier_new();

    vsc_data_t signature_data = vsc_buffer_data(signature);
    for (auto _ : state) {
        (void)vscf_verifier_reset(verifier, signature_data);
        vscf_verifier_append_data(verifier, k_data);
        (void)vscf_verifier_verify(verifier, public_key);
    }

    vscf_verifier_destroy(&verifier);
    vsc_buffer_destroy(&signature);
    vscf_signer_destroy(&signer);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&rng);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


BENCHMARK(signer_sign)->ArgNames({"Ed25519"})->Arg(vscf_alg_id_ED25519);
BENCHMARK(signer_sign)->ArgNames({"secp256r1"})->Arg(vscf_alg_id_SECP256R1);
BENCHMARK(signer_sign)->ArgNames({"RSA"})->Args({vscf_alg_id_RSA, 4096});

BENCHMARK(verifier_verify)->ArgNames({"Ed25519"})->Arg(vscf_alg_id_ED25519);
BENCHMARK(verifier_verify)->ArgNames({"secp256r1"})->Arg(vscf_alg_id_SECP256R1);
BENCHMARK(verifier_verify)->ArgNames({"RSA"})->Args({vscf_alg_id_RSA, 4096});
