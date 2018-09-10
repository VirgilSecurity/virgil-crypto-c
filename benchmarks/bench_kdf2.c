//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include "vscf_hash_info.h"
#include "vscf_hash.h"
#include "vscf_hash_stream.h"
#include "vscf_kdf2.h"
#include "vscf_sha256.h"
#include "vscf_assert.h"
#include "vscf_memory.h"

#include "data/include/bench_data_kdf2.h"
#include "benchmark/include/benchmark.h"

// --------------------------------------------------------------------------
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------

void benchmark_kdf2_native(void * data, size_t data_size)
{
    vscf_kdf2_impl_t *kdf2_impl = vscf_kdf2_new();
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_kdf2_VECTOR_1_KEY.len);

    vscf_kdf2_take_hash_stream(kdf2_impl, vscf_sha256_impl(vscf_sha256_new()));

    vscf_kdf2_derive(kdf2_impl, *(vsc_data_t *)data, key, vsc_buffer_capacity(key));

    vsc_buffer_destroy(&key);
    vscf_kdf2_destroy(&kdf2_impl);
}

void benchmark_kdf2_interface(void * data, size_t data_size)
{
    vscf_kdf2_impl_t *kdf2_impl = vscf_kdf2_new();
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_kdf2_VECTOR_1_KEY.len);

    vscf_kdf2_take_hash_stream(kdf2_impl, vscf_sha256_impl(vscf_sha256_new()));

    vscf_kdf_derive(vscf_kdf2_impl(kdf2_impl), *(vsc_data_t *)data, key, vsc_buffer_capacity(key));

    vsc_buffer_destroy(&key);
    vscf_kdf2_destroy(&kdf2_impl);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    benchmark(benchmark_kdf2_native, (void *)&test_kdf2_VECTOR_1_DATA, 0, 1000000);
    benchmark(benchmark_kdf2_interface, (void *)&test_kdf2_VECTOR_1_DATA, 0, 1000000);
}
