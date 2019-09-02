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

#include "vscf_hash.h"
#include "vscf_sha256.h"
#include "vscf_sha512.h"

#include "vscf_fake_random.h"


static void
hash_data(benchmark::State &state, vscf_impl_t *hash, size_t data_size) {

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(data_size);
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_hash_digest_len(vscf_hash_api(hash)));

    vscf_fake_random_t *rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(rng, 0x0A);
    (void)vscf_fake_random_random(rng, data_size, data);

    for (auto _ : state) {
        vscf_hash_start(hash);
        vscf_hash_update(hash, vsc_buffer_data(data));
        vscf_hash_finish(hash, digest);

        vsc_buffer_reset(digest);
    }

    vscf_fake_random_destroy(&rng);
    vsc_buffer_destroy(&data);
    vsc_buffer_destroy(&digest);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}

static void
hash__sha256__8192_bytes(benchmark::State &state) {
    vscf_sha256_t *sha256 = vscf_sha256_new();
    hash_data(state, vscf_sha256_impl(sha256), 8192);
    vscf_sha256_destroy(&sha256);
}

static void
hash__sha512__8192_bytes(benchmark::State &state) {
    vscf_sha512_t *sha512 = vscf_sha512_new();
    hash_data(state, vscf_sha512_impl(sha512), 8192);
    vscf_sha512_destroy(&sha512);
}

BENCHMARK(hash__sha256__8192_bytes);
BENCHMARK(hash__sha512__8192_bytes);
