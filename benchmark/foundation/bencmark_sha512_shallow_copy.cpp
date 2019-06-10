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
#include "test_data_sha512.h"

static void
benchmark__shallow_copy(benchmark::State &state) {
    vscf_sha512_t *sha512 = vscf_sha512_new();

    for (auto _ : state) {
        vscf_sha512_t *sha512_copy = vscf_sha512_shallow_copy(sha512);
        state.PauseTiming();
        vscf_sha512_delete(sha512_copy);
        state.ResumeTiming();
    }

    vscf_sha512_destroy(&sha512);
}

static void
benchmark__shallow_copy_delete(benchmark::State &state) {
    vscf_sha512_t *sha512 = vscf_sha512_new();

    for (auto _ : state) {
        state.PauseTiming();
        vscf_sha512_t *sha512_copy = vscf_sha512_shallow_copy(sha512);
        state.ResumeTiming();
        vscf_sha512_delete(sha512_copy);
    }

    vscf_sha512_destroy(&sha512);
}

BENCHMARK(benchmark__shallow_copy);
BENCHMARK(benchmark__shallow_copy_delete);

BENCHMARK_MAIN();
