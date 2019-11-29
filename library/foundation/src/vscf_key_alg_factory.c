//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Create a bridge between "raw keys" and algorithms that can import them.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_alg_factory.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_key.h"
#include "vscf_random.h"
#include "vscf_rsa.h"
#include "vscf_ecc.h"
#include "vscf_ed25519.h"
#include "vscf_curve25519.h"
#include "vscf_compound_key_alg.h"
#include "vscf_chained_key_alg.h"
#include "vscf_falcon.h"
#include "vscf_round5.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Create a key algorithm based on an identifier.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_t alg_id, const vscf_impl_t *random, vscf_error_t *error) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    if (random) {
        VSCF_ASSERT(vscf_random_is_implemented(random));
    }

    vscf_ecies_t *ecies = NULL;

    switch (alg_id) {
#if VSCF_ECC || VSCF_CURVE25519 || VSCF_ED25519
    case vscf_alg_id_ECC:
    case vscf_alg_id_SECP256R1:
    case vscf_alg_id_ED25519:
    case vscf_alg_id_CURVE25519: {
        ecies = vscf_ecies_new();
        if (random) {
            vscf_ecies_use_random(ecies, (vscf_impl_t *)random);
        }
        vscf_ecies_setup_defaults_no_random(ecies);
    } break;
    default:
        //  Do nothing
        break;
    }
#endif // VSCF_ECC || VSCF_CURVE25519 || VSCF_ED25519

    switch (alg_id) {
#if VSCF_RSA
    case vscf_alg_id_RSA: {
        vscf_rsa_t *rsa = vscf_rsa_new();
        if (random) {
            vscf_rsa_use_random(rsa, (vscf_impl_t *)random);
        }
        return vscf_rsa_impl(rsa);
    }
#endif // VSCF_RSA

#if VSCF_ED25519
    case vscf_alg_id_ED25519: {
        vscf_ed25519_t *ed25519 = vscf_ed25519_new();
        if (random) {
            vscf_ed25519_use_random(ed25519, (vscf_impl_t *)random);
        }
        vscf_ed25519_take_ecies(ed25519, ecies);
        return vscf_ed25519_impl(ed25519);
    }
#endif // VSCF_ED25519

#if VSCF_CURVE25519
    case vscf_alg_id_CURVE25519: {
        vscf_curve25519_t *curve25519 = vscf_curve25519_new();
        if (random) {
            vscf_curve25519_use_random(curve25519, (vscf_impl_t *)random);
        }
        vscf_curve25519_take_ecies(curve25519, ecies);
        return vscf_curve25519_impl(curve25519);
    }
#endif // VSCF_CURVE25519

#if VSCF_ECC
    case vscf_alg_id_ECC:
    case vscf_alg_id_SECP256R1: {
        vscf_ecc_t *ecc = vscf_ecc_new();
        if (random) {
            vscf_ecc_use_random(ecc, (vscf_impl_t *)random);
        }
        vscf_ecc_take_ecies(ecc, ecies);
        return vscf_ecc_impl(ecc);
    }
#endif // VSCF_ECC

#if VSCF_COMPOUND_KEY_ALG
    case vscf_alg_id_COMPOUND_KEY: {
        vscf_compound_key_alg_t *compound_key_alg = vscf_compound_key_alg_new();
        if (random) {
            vscf_compound_key_alg_use_random(compound_key_alg, (vscf_impl_t *)random);
        }
        return vscf_compound_key_alg_impl(compound_key_alg);
    }
#endif // VSCF_COMPOUND_KEY_ALG

#if VSCF_CHAINED_KEY_ALG
    case vscf_alg_id_CHAINED_KEY: {
        vscf_chained_key_alg_t *chained_key_alg = vscf_chained_key_alg_new();
        if (random) {
            vscf_chained_key_alg_use_random(chained_key_alg, (vscf_impl_t *)random);
        }
        return vscf_chained_key_alg_impl(chained_key_alg);
    }
#endif // VSCF_CHAINED_KEY_ALG

#if VSCF_POST_QUANTUM
#if VSCF_FALCON
    case vscf_alg_id_FALCON: {
        vscf_falcon_t *falcon = vscf_falcon_new();
        if (random) {
            vscf_falcon_use_random(falcon, (vscf_impl_t *)random);
        }
        return vscf_falcon_impl(falcon);
    }
#endif // VSCF_FALCON

#if VSCF_ROUND5
    case vscf_alg_id_ROUND5:
    case vscf_alg_id_ROUND5_ND_5PKE_5D: {
        vscf_round5_t *round5 = vscf_round5_new();
        if (random) {
            vscf_round5_use_random(round5, (vscf_impl_t *)random);
        }
        return vscf_round5_impl(round5);
    }
#endif // VSCF_ROUND5
#endif // VSCF_POST_QUANTUM

    default:
        vscf_ecies_destroy(&ecies);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }
}

//
//  Create a key algorithm correspond to a specific key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_key(const vscf_impl_t *key, const vscf_impl_t *random, vscf_error_t *error) {

    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));
    VSCF_ASSERT(vscf_key_alg_id(key) != vscf_alg_id_NONE);

    if (random) {
        VSCF_ASSERT(vscf_random_is_implemented(random));
    }

    const vscf_impl_tag_t impl_tag = vscf_key_impl_tag(key);
    switch (impl_tag) {
    case vscf_impl_tag_RSA:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_RSA, random, error);

    case vscf_impl_tag_ECC:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_ECC, random, error);

    case vscf_impl_tag_ED25519:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_ED25519, random, error);

    case vscf_impl_tag_CURVE25519:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_CURVE25519, random, error);

    case vscf_impl_tag_COMPOUND_KEY_ALG:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_COMPOUND_KEY, random, error);

    case vscf_impl_tag_CHAINED_KEY_ALG:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_CHAINED_KEY, random, error);

    case vscf_impl_tag_FALCON:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_FALCON, random, error);

    case vscf_impl_tag_ROUND5:
        return vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_ROUND5, random, error);

    default:
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }
}

//
//  Create a key algorithm that can import "raw public key".
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_raw_public_key(
        const vscf_raw_public_key_t *public_key, const vscf_impl_t *random, vscf_error_t *error) {

    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));

    if (random) {
        VSCF_ASSERT(vscf_random_is_implemented(random));
    }

    vscf_impl_t *key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_raw_public_key_alg_id(public_key), random, error);
    return key_alg;
}

//
//  Create a key algorithm that can import "raw private key".
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_factory_create_from_raw_private_key(
        const vscf_raw_private_key_t *private_key, const vscf_impl_t *random, vscf_error_t *error) {

    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));

    if (random) {
        VSCF_ASSERT(vscf_random_is_implemented(random));
    }

    vscf_impl_t *key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_raw_private_key_alg_id(private_key), random, error);
    return key_alg;
}
