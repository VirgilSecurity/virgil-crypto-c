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

#include "benchmark_data.h"
#include "vscf_alg.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_verifier.h"


static void
benchmark__reset__with_ed25519_sha384_signature__format_is_valid(benchmark::State &state) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    VSCF_UNUSED(vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, benchmark_signer_ED25519_PUBLIC_KEY_PKCS8, NULL);
    vscf_verifier_t *verifier = vscf_verifier_new();

    for (auto _ : state) {
        VSCF_UNUSED(vscf_verifier_reset(verifier, benchmark_signer_ED25519_SHA384_SIGNATURE));
        vscf_verifier_update(verifier, benchmark_signer_DATA);
        vscf_verifier_verify(verifier, public_key);
    }

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
benchmark__verify__ed25519_sha384_signature_v2_compat_with_public_key(benchmark::State &state) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, benchmark_signer_ED25519_PUBLIC_KEY_PKCS8, NULL);

    vscf_verifier_t *verifier = vscf_verifier_new();

    for (auto _ : state) {
        VSCF_UNUSED(vscf_verifier_reset(verifier, benchmark_signer_ED25519_SHA384_SIGNATURE_V2_COMPAT));
        vscf_verifier_update(verifier, benchmark_signer_DATA);
        vscf_verifier_verify(verifier, public_key);
    }

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
benchmark__verify__rsa2048_sha384_signature_with_public_key(benchmark::State &state) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, benchmark_signer_RSA2048_PUBLIC_KEY_PKCS8, NULL);

    vscf_verifier_t *verifier = vscf_verifier_new();

    for (auto _ : state) {
        VSCF_UNUSED(vscf_verifier_reset(verifier, benchmark_signer_RSA2048_SHA384_SIGNATURE));
        vscf_verifier_update(verifier, benchmark_signer_DATA);
        vscf_verifier_verify(verifier, public_key);
    }

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
benchmark__verify__rsa2048_sha384_signature_v2_compat_with_public_key(benchmark::State &state) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, benchmark_signer_RSA2048_PUBLIC_KEY_PKCS8, NULL);

    vscf_verifier_t *verifier = vscf_verifier_new();

    for (auto _ : state) {
        VSCF_UNUSED(vscf_verifier_reset(verifier, benchmark_signer_RSA2048_SHA384_SIGNATURE_V2_COMPAT));
        vscf_verifier_update(verifier, benchmark_signer_DATA);
        vscf_verifier_verify(verifier, public_key);
    }

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}


BENCHMARK(benchmark__reset__with_ed25519_sha384_signature__format_is_valid);
BENCHMARK(benchmark__verify__ed25519_sha384_signature_v2_compat_with_public_key);
BENCHMARK(benchmark__verify__rsa2048_sha384_signature_with_public_key);
BENCHMARK(benchmark__verify__rsa2048_sha384_signature_v2_compat_with_public_key);
