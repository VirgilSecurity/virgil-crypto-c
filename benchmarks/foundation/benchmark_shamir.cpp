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

#include "vscf_shamir.h"
#include "vscf_fake_random.h"


//  A 32-byte secret (the typical symmetric key being split).
static const size_t k_secret_len = 32;


static vscf_shamir_t *
new_shamir_with_fake_random(void) {
    vscf_shamir_t *shamir = vscf_shamir_new();

    vscf_fake_random_t *rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(rng, 0xAB);
    //  use_random takes a shared reference, so the local handle can be released.
    vscf_shamir_use_random(shamir, vscf_fake_random_impl(rng));
    vscf_fake_random_destroy(&rng);

    return shamir;
}


static void
shamir_split(benchmark::State &state, size_t threshold, size_t share_count) {
    vscf_shamir_t *shamir = new_shamir_with_fake_random();

    vsc_buffer_t *secret = vsc_buffer_new_with_capacity(k_secret_len);
    vsc_buffer_make_secure(secret);
    {
        vscf_fake_random_t *rng = vscf_fake_random_new();
        vscf_fake_random_setup_source_byte(rng, 0x0A);
        (void)vscf_fake_random_random(rng, k_secret_len, secret);
        vscf_fake_random_destroy(&rng);
    }

    vsc_buffer_t *shares = vsc_buffer_new_with_capacity(vscf_shamir_shares_len(shamir, k_secret_len, share_count));

    for (auto _ : state) {
        (void)vscf_shamir_split(shamir, vsc_buffer_data(secret), threshold, share_count, shares);
        vsc_buffer_reset(shares);
    }

    vsc_buffer_destroy(&secret);
    vsc_buffer_destroy(&shares);
    vscf_shamir_destroy(&shamir);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


static void
shamir_combine(benchmark::State &state, size_t threshold, size_t share_count, size_t use_count) {
    vscf_shamir_t *shamir = new_shamir_with_fake_random();

    vsc_buffer_t *secret = vsc_buffer_new_with_capacity(k_secret_len);
    vsc_buffer_make_secure(secret);
    {
        vscf_fake_random_t *rng = vscf_fake_random_new();
        vscf_fake_random_setup_source_byte(rng, 0x0A);
        (void)vscf_fake_random_random(rng, k_secret_len, secret);
        vscf_fake_random_destroy(&rng);
    }

    //  Produce the shares once, outside the measured loop.
    vsc_buffer_t *shares = vsc_buffer_new_with_capacity(vscf_shamir_shares_len(shamir, k_secret_len, share_count));
    (void)vscf_shamir_split(shamir, vsc_buffer_data(secret), threshold, share_count, shares);

    //  Select the first `use_count` shares into one contiguous buffer.
    const size_t share_size = vsc_buffer_len(shares) / share_count;
    vsc_buffer_t *selection = vsc_buffer_new_with_capacity(share_size * use_count);
    for (size_t i = 0; i < use_count; ++i) {
        vsc_buffer_write_data(selection, vsc_data(vsc_buffer_bytes(shares) + i * share_size, share_size));
    }

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_shamir_recovered_secret_len(shamir, vsc_buffer_len(selection), use_count));
    vsc_buffer_make_secure(out);

    for (auto _ : state) {
        (void)vscf_shamir_combine(shamir, vsc_buffer_data(selection), use_count, out);
        vsc_buffer_reset(out);
    }

    vsc_buffer_destroy(&secret);
    vsc_buffer_destroy(&shares);
    vsc_buffer_destroy(&selection);
    vsc_buffer_destroy(&out);
    vscf_shamir_destroy(&shamir);

    state.counters["op"] = benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
}


static void
shamir__split__2_of_3(benchmark::State &state) {
    shamir_split(state, 2, 3);
}

static void
shamir__split__3_of_5(benchmark::State &state) {
    shamir_split(state, 3, 5);
}

static void
shamir__combine__2_of_3(benchmark::State &state) {
    shamir_combine(state, 2, 3, 2);
}

static void
shamir__combine__3_of_5(benchmark::State &state) {
    shamir_combine(state, 3, 5, 3);
}

BENCHMARK(shamir__split__2_of_3);
BENCHMARK(shamir__split__3_of_5);
BENCHMARK(shamir__combine__2_of_3);
BENCHMARK(shamir__combine__3_of_5);
