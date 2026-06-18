//  Copyright (C) 2015-2026 Virgil Security, Inc.
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

#include "vscf_aes256_kw.h"
#include "vscf_fake_random.h"


//  AES-256 Key Wrap: the key-encryption key (KEK) is 256-bit (32 bytes); the
//  wrapped payload must be a multiple of 8 bytes (here a 256-bit data key).
static const size_t k_kek_len = 32;


static void
kw_wrap(benchmark::State &state, size_t data_len) {
    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();

    vsc_buffer_t *kek = vsc_buffer_new_with_capacity(k_kek_len);
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(data_len);
    {
        vscf_fake_random_t *rng = vscf_fake_random_new();
        vscf_fake_random_setup_source_byte(rng, 0x0A);
        (void)vscf_fake_random_random(rng, k_kek_len, kek);
        (void)vscf_fake_random_random(rng, data_len, data);
        vscf_fake_random_destroy(&rng);
    }

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_kw_wrapped_len(kw, data_len));

    for (auto _ : state) {
        (void)vscf_aes256_kw_wrap(kw, vsc_buffer_data(kek), vsc_buffer_data(data), out);
        vsc_buffer_reset(out);
    }

    vsc_buffer_destroy(&kek);
    vsc_buffer_destroy(&data);
    vsc_buffer_destroy(&out);
    vscf_aes256_kw_destroy(&kw);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


static void
kw_unwrap(benchmark::State &state, size_t data_len) {
    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();

    vsc_buffer_t *kek = vsc_buffer_new_with_capacity(k_kek_len);
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(data_len);
    {
        vscf_fake_random_t *rng = vscf_fake_random_new();
        vscf_fake_random_setup_source_byte(rng, 0x0A);
        (void)vscf_fake_random_random(rng, k_kek_len, kek);
        (void)vscf_fake_random_random(rng, data_len, data);
        vscf_fake_random_destroy(&rng);
    }

    //  Wrap once, outside the measured loop.
    vsc_buffer_t *wrapped = vsc_buffer_new_with_capacity(vscf_aes256_kw_wrapped_len(kw, data_len));
    (void)vscf_aes256_kw_wrap(kw, vsc_buffer_data(kek), vsc_buffer_data(data), wrapped);

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_kw_unwrapped_len(kw, vsc_buffer_len(wrapped)));

    for (auto _ : state) {
        (void)vscf_aes256_kw_unwrap(kw, vsc_buffer_data(kek), vsc_buffer_data(wrapped), out);
        vsc_buffer_reset(out);
    }

    vsc_buffer_destroy(&kek);
    vsc_buffer_destroy(&data);
    vsc_buffer_destroy(&wrapped);
    vsc_buffer_destroy(&out);
    vscf_aes256_kw_destroy(&kw);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


static void
aes256_kw__wrap__32_bytes(benchmark::State &state) {
    kw_wrap(state, 32);
}

static void
aes256_kw__unwrap__32_bytes(benchmark::State &state) {
    kw_unwrap(state, 32);
}

BENCHMARK(aes256_kw__wrap__32_bytes);
BENCHMARK(aes256_kw__unwrap__32_bytes);
