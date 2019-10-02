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
#include "vscf_key_alg_factory.h"


static void
generate_exported_key(benchmark::State &state) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    (void)vscf_key_provider_setup_defaults(key_provider);

    const vscf_alg_id_t alg_id = (vscf_alg_id_t)state.range(0);
    if (alg_id == vscf_alg_id_RSA) {
        const size_t bitlen = (size_t)state.range(1);
        vscf_key_provider_set_rsa_params(key_provider, bitlen);
    }

    for (auto _ : state) {
        vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, NULL);

        const size_t key_buf_len = vscf_key_provider_exported_private_key_len(key_provider, private_key);
        vsc_buffer_t *key_buf = vsc_buffer_new_with_capacity(key_buf_len);
        (void)vscf_key_provider_export_private_key(key_provider, private_key, key_buf);

        vsc_buffer_destroy(&key_buf);
        vscf_impl_destroy(&private_key);
    }

    vscf_key_provider_destroy(&key_provider);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}

BENCHMARK(generate_exported_key)->ArgNames({"Ed25519"})->Arg(vscf_alg_id_ED25519);
BENCHMARK(generate_exported_key)->ArgNames({"secp256r1"})->Arg(vscf_alg_id_SECP256R1);
BENCHMARK(generate_exported_key)->ArgNames({"RSA"})->Args({vscf_alg_id_RSA, 4096});
