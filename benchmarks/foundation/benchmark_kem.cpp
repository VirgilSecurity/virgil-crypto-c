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

#include "vscf_kem.h"
#include "vscf_round5.h"
#include "vscf_curve25519.h"
#include "vscf_key_provider.h"
#include "vscf_key_alg_factory.h"
#include "vscf_private_key.h"
#include "vscf_assert.h"

#include "vscf_fake_random.h"


static void
kem_encapsulate(benchmark::State &state) {

    //
    //  Prepera algs
    //
    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    (void)vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(alg_id, random, NULL);

    //
    //  Generate keys
    //
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    //
    //  Prepare vars
    //
    const size_t shared_key_len = vscf_kem_kem_shared_key_len(key_alg, public_key);
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(shared_key_len);

    const size_t encapsulated_key_len = vscf_kem_kem_encapsulated_key_len(key_alg, public_key);
    vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(encapsulated_key_len);

    //
    //  Measure
    //
    for (auto _ : state) {
        const vscf_status_t status = vscf_kem_kem_encapsulate(key_alg, public_key, shared_key, encapsulated_key);
        vsc_buffer_reset(shared_key);
        vsc_buffer_reset(encapsulated_key);
        VSCF_ASSERT(status == vscf_status_SUCCESS);
    }

    vscf_fake_random_destroy(&fake_random);
    vscf_impl_destroy(&key_alg);
    vscf_key_provider_destroy(&key_provider);
    vsc_buffer_destroy(&shared_key);
    vsc_buffer_destroy(&encapsulated_key);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}

static void
kem_decapsulate(benchmark::State &state) {

    //
    //  Prepera algs
    //
    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    (void)vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(alg_id, random, NULL);

    //
    //  Generate keys
    //
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    //
    //  Prepare vars
    //
    const size_t shared_key_len = vscf_kem_kem_shared_key_len(key_alg, public_key);
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(shared_key_len);

    const size_t encapsulated_key_len = vscf_kem_kem_encapsulated_key_len(key_alg, public_key);
    vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(encapsulated_key_len);

    (void)vscf_kem_kem_encapsulate(key_alg, public_key, shared_key, encapsulated_key);
    vsc_buffer_reset(shared_key);

    //
    //  Measure
    //
    for (auto _ : state) {
        const vscf_status_t status = vscf_kem_kem_decapsulate(key_alg, vsc_buffer_data(encapsulated_key), private_key, shared_key);
        vsc_buffer_reset(shared_key);
        VSCF_ASSERT(status == vscf_status_SUCCESS);
    }

    vscf_fake_random_destroy(&fake_random);
    vscf_impl_destroy(&key_alg);
    vscf_key_provider_destroy(&key_provider);
    vsc_buffer_destroy(&shared_key);
    vsc_buffer_destroy(&encapsulated_key);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}

BENCHMARK(kem_encapsulate)->ArgNames({"Curve25519"})->Arg(vscf_alg_id_CURVE25519);
BENCHMARK(kem_encapsulate)->ArgNames({"Round5"})->Arg(vscf_alg_id_ROUND5_ND_5KEM_5D);

BENCHMARK(kem_decapsulate)->ArgNames({"Curve25519"})->Arg(vscf_alg_id_CURVE25519);
BENCHMARK(kem_decapsulate)->ArgNames({"Round5"})->Arg(vscf_alg_id_ROUND5_ND_5KEM_5D);
