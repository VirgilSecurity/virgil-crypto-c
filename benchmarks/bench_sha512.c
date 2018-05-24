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

#include "vsf_hash_info.h"
#include "vsf_hash.h"
#include "vsf_hash_stream.h"
#include "vsf_sha512.h"
#include "vsf_assert.h"
#include "vsf_hash_api.h"
#include "vsf_hash_stream.h"

#include "data/include/bench_data_sha512.h"
#include "benchmark/include/benchmark.h"

// --------------------------------------------------------------------------
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------

void benchmark_sha512_native(void * data, size_t data_size)
{
    byte digest[vsf_sha512_DIGEST_SIZE] = { 0x00 };

    vsf_sha512_hash(data, data_size, digest, vsf_sha512_DIGEST_SIZE);
}

void benchmark_sha512_interface(void * data, size_t data_size)
{
    byte digest[vsf_sha512_DIGEST_SIZE] = { 0x00 };

    vsf_impl_t *impl = vsf_sha512_impl(vsf_sha512_new());

    vsf_hash_stream_start (impl);
    vsf_hash_stream_update (impl, data, data_size);
    vsf_hash_stream_finish(impl, digest, vsf_sha512_DIGEST_SIZE);

    vsf_impl_destroy (&impl);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    benchmark2(benchmark_sha512_native, "SHA512 (native)", benchmark_sha512_interface, "(interface)", (void*) test_sha512_VECTOR_1_DIGEST, test_sha512_VECTOR_1_DIGEST_LEN, 1000000);
}
