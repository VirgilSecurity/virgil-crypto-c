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
//  Provide functionality for private key generation and importing that
//  relies on the software default implementations.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_provider.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_key_provider_defs.h"
#include "vscf_key_alg.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_key_serializer.h"
#include "vscf_key_deserializer.h"
#include "vscf_key_alg_factory.h"
#include "vscf_ctr_drbg.h"
#include "vscf_key_asn1_deserializer.h"
#include "vscf_key_asn1_serializer.h"
#include "vscf_rsa.h"
#include "vscf_ed25519.h"
#include "vscf_curve25519.h"
#include "vscf_ecc.h"
#include "vscf_falcon.h"
#include "vscf_round5.h"
#include "vscf_compound_key_alg.h"
#include "vscf_compound_key_alg_defs.h"
#include "vscf_chained_key_alg.h"
#include "vscf_chained_key_alg_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_provider_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_provider_init_ctx(vscf_key_provider_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_provider_cleanup_ctx(vscf_key_provider_t *self);

//
//  Return size of 'vscf_key_provider_t'.
//
VSCF_PUBLIC size_t
vscf_key_provider_ctx_size(void) {

    return sizeof(vscf_key_provider_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_provider_init(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_key_provider_t));

    self->refcnt = 1;

    vscf_key_provider_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_provider_cleanup(vscf_key_provider_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_key_provider_cleanup_ctx(self);

    vscf_key_provider_release_random(self);

    vscf_zeroize(self, sizeof(vscf_key_provider_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_provider_t *
vscf_key_provider_new(void) {

    vscf_key_provider_t *self = (vscf_key_provider_t *) vscf_alloc(sizeof (vscf_key_provider_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_key_provider_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_provider_delete(vscf_key_provider_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_key_provider_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_provider_new ()'.
//
VSCF_PUBLIC void
vscf_key_provider_destroy(vscf_key_provider_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_key_provider_t *self = *self_ref;
    *self_ref = NULL;

    vscf_key_provider_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_provider_t *
vscf_key_provider_shallow_copy(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_key_provider_use_random(vscf_key_provider_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_key_provider_take_random(vscf_key_provider_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_key_provider_release_random(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_provider_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_provider_init_ctx(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    self->rsa_bitlen = 2048;

    vscf_key_asn1_serializer_t *key_asn1_serializer = vscf_key_asn1_serializer_new();
    vscf_key_asn1_serializer_setup_defaults(key_asn1_serializer);
    self->key_asn1_serializer = vscf_key_asn1_serializer_impl(key_asn1_serializer);

    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer);
    self->key_asn1_deserializer = vscf_key_asn1_deserializer_impl(key_asn1_deserializer);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_provider_cleanup_ctx(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->key_asn1_serializer);
    vscf_impl_destroy(&self->key_asn1_deserializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_key_provider_setup_defaults(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }
        self->random = vscf_ctr_drbg_impl(random);
    }

    return vscf_status_SUCCESS;
}

//
//  Setup parameters that is used during RSA key generation.
//
VSCF_PUBLIC void
vscf_key_provider_set_rsa_params(vscf_key_provider_t *self, size_t bitlen) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(bitlen >= 2048 && bitlen <= 16384);
    VSCF_ASSERT(bitlen % 2 == 0);

    self->rsa_bitlen = bitlen;
}

//
//  Generate new private key with a given algorithm.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_private_key(vscf_key_provider_t *self, vscf_alg_id_t alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    vscf_impl_t *key = NULL;

    switch (alg_id) {
#if VSCF_RSA
    case vscf_alg_id_RSA: {
        vscf_rsa_t *rsa = vscf_rsa_new();
        vscf_rsa_use_random(rsa, self->random);
        key = vscf_rsa_generate_key(rsa, self->rsa_bitlen, error);
        vscf_rsa_destroy(&rsa);
        break;
    }
#endif // VSCF_RSA

#if VSCF_ED25519
    case vscf_alg_id_ED25519: {
        vscf_ed25519_t *ed25519 = vscf_ed25519_new();
        vscf_ed25519_use_random(ed25519, self->random);
        key = vscf_ed25519_generate_key(ed25519, error);
        vscf_ed25519_destroy(&ed25519);
        break;
    }
#endif // VSCF_ED25519

#if VSCF_CURVE25519
    case vscf_alg_id_CURVE25519: {
        vscf_curve25519_t *curve25519 = vscf_curve25519_new();
        vscf_curve25519_use_random(curve25519, self->random);
        key = vscf_curve25519_generate_key(curve25519, error);
        vscf_curve25519_destroy(&curve25519);
        break;
    }
#endif // VSCF_CURVE25519

#if VSCF_ECC
    case vscf_alg_id_SECP256R1: {
        vscf_ecc_t *ecc = vscf_ecc_new();
        vscf_ecc_use_random(ecc, self->random);
        key = vscf_ecc_generate_key(ecc, alg_id, error);
        vscf_ecc_destroy(&ecc);
        break;
    }
#endif // VSCF_ECC

#if VSCF_POST_QUANTUM
#if VSCF_FALCON
    case vscf_alg_id_FALCON: {
        vscf_falcon_t *falcon = vscf_falcon_new();
        vscf_falcon_use_random(falcon, self->random);
        key = vscf_falcon_generate_key(falcon, error);
        vscf_falcon_destroy(&falcon);
        break;
    }
#endif // VSCF_FALCON

#if VSCF_ROUND5
    case vscf_alg_id_ROUND5:
    case vscf_alg_id_ROUND5_ND_5PKE_5D: {
        vscf_round5_t *round5 = vscf_round5_new();
        key = vscf_round5_generate_key(round5, error);
        vscf_round5_destroy(&round5);
        break;
    }
#endif // VSCF_ROUND5
#endif // VSCF_POST_QUANTUM

    default:
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    return key;
}

//
//  Generate new compound private key with given algorithms.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_compound_private_key(
        vscf_key_provider_t *self, vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(cipher_alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(signer_alg_id != vscf_alg_id_NONE);

#if VSCF_COMPOUND_KEY_ALG
    //
    //  Configure a;gs.
    //
    vscf_compound_key_alg_t compound_key_alg;
    vscf_compound_key_alg_init(&compound_key_alg);
    vscf_compound_key_alg_use_random(&compound_key_alg, self->random);

    const vscf_status_t status = vscf_compound_key_alg_setup_defaults(&compound_key_alg);
    VSCF_ASSERT(status == vscf_status_SUCCESS);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *compound_key = NULL;
    vscf_impl_t *cipher_key = NULL;
    vscf_impl_t *signer_key = NULL;

    //
    //  Generate keys.
    //
    cipher_key = vscf_key_provider_generate_private_key(self, cipher_alg_id, error);
    if (NULL == cipher_key) {
        goto cleanup;
    }

    signer_key = vscf_key_provider_generate_private_key(self, signer_alg_id, error);
    if (NULL == signer_key) {
        goto cleanup;
    }

    compound_key = vscf_compound_key_alg_make_key(&compound_key_alg, cipher_key, signer_key, error);

cleanup:
    vscf_impl_destroy(&cipher_key);
    vscf_impl_destroy(&signer_key);
    vscf_compound_key_alg_cleanup(&compound_key_alg);
    return compound_key;
#else
    VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
    return NULL;
#endif // VSCF_COMPOUND_KEY_ALG
}

//
//  Generate new compound private key with post-quantum algorithms.
//
//  Note, cipher should not be post-quantum.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_post_quantum_private_key(
        vscf_key_provider_t *self, vscf_alg_id_t cipher_alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(cipher_alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(cipher_alg_id != vscf_alg_id_ROUND5);
    VSCF_ASSERT(cipher_alg_id != vscf_alg_id_ROUND5_ND_5PKE_5D);
#if VSCF_POST_QUANTUM && VSCF_COMPOUND_KEY_ALG && VSCF_CHAINED_KEY_ALG
    //
    //  Configure a;algs.
    //
    vscf_compound_key_alg_t compound_key_alg;
    vscf_compound_key_alg_init(&compound_key_alg);
    vscf_compound_key_alg_use_random(&compound_key_alg, self->random);

    const vscf_status_t status = vscf_compound_key_alg_setup_defaults(&compound_key_alg);
    VSCF_ASSERT(status == vscf_status_SUCCESS);

    vscf_chained_key_alg_t chained_key_alg;
    vscf_chained_key_alg_init(&chained_key_alg);
    vscf_chained_key_alg_use_random(&chained_key_alg, self->random);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *compound_key = NULL;
    vscf_impl_t *chained_cipher_key = NULL;
    vscf_impl_t *cipher_key = NULL;
    vscf_impl_t *pq_cipher_key = NULL;
    vscf_impl_t *signer_key = NULL;

    //
    //  Generate keys.
    //
    cipher_key = vscf_key_provider_generate_private_key(self, cipher_alg_id, error);
    if (NULL == cipher_key) {
        goto cleanup;
    }

    pq_cipher_key = vscf_key_provider_generate_private_key(self, vscf_alg_id_ROUND5_ND_5PKE_5D, error);
    if (NULL == pq_cipher_key) {
        goto cleanup;
    }

    signer_key = vscf_key_provider_generate_private_key(self, vscf_alg_id_FALCON, error);
    if (NULL == signer_key) {
        goto cleanup;
    }

    chained_cipher_key = vscf_chained_key_alg_make_key(&chained_key_alg, cipher_key, pq_cipher_key, error);
    if (NULL == chained_cipher_key) {
        goto cleanup;
    }

    compound_key = vscf_compound_key_alg_make_key(&compound_key_alg, chained_cipher_key, signer_key, error);

cleanup:
    vscf_impl_destroy(&cipher_key);
    vscf_impl_destroy(&pq_cipher_key);
    vscf_impl_destroy(&signer_key);
    vscf_impl_destroy(&chained_cipher_key);
    vscf_compound_key_alg_cleanup(&compound_key_alg);
    vscf_chained_key_alg_cleanup(&chained_key_alg);
    return compound_key;
#else  // VSCF_POST_QUANTUM && VSCF_COMPOUND_KEY_ALG && VSCF_CHAINED_KEY_ALG
    VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
    return NULL;
#endif // VSCF_POST_QUANTUM && VSCF_COMPOUND_KEY_ALG && VSCF_CHAINED_KEY_ALG
}

//
//  Import private key from the PKCS#8 format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_import_private_key(vscf_key_provider_t *self, vsc_data_t key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->key_asn1_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(key_data));

    vscf_raw_private_key_t *raw_private_key =
            vscf_key_deserializer_deserialize_private_key(self->key_asn1_deserializer, key_data, error);

    if (raw_private_key == NULL) {
        return NULL;
    }

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_raw_private_key(raw_private_key, self->random, error);
    if (key_alg == NULL) {
        vscf_raw_private_key_destroy(&raw_private_key);
        return NULL;
    }

    vscf_impl_t *private_key = vscf_key_alg_import_private_key(key_alg, raw_private_key, error);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&key_alg);

    return private_key;
}

//
//  Import public key from the PKCS#8 format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_import_public_key(vscf_key_provider_t *self, vsc_data_t key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->key_asn1_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(key_data));

    vscf_raw_public_key_t *raw_public_key =
            vscf_key_deserializer_deserialize_public_key(self->key_asn1_deserializer, key_data, error);

    if (raw_public_key == NULL) {
        return NULL;
    }

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_raw_public_key(raw_public_key, self->random, error);
    if (key_alg == NULL) {
        vscf_raw_public_key_destroy(&raw_public_key);
        return NULL;
    }

    vscf_impl_t *public_key = vscf_key_alg_import_public_key(key_alg, raw_public_key, error);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&key_alg);

    return public_key;
}

//
//  Calculate buffer size enough to hold exported public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_provider_exported_public_key_len(vscf_key_provider_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_asn1_serializer);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(public_key, self->random, &error);
    VSCF_ASSERT_PTR(key_alg);

    vscf_raw_public_key_t *raw_public_key = vscf_key_alg_export_public_key(key_alg, public_key, &error);
    if (vscf_error_has_error(&error)) {
        vscf_impl_destroy(&key_alg);
        return vscf_error_status(&error);
    }

    const size_t len = vscf_key_serializer_serialized_public_key_len(self->key_asn1_serializer, raw_public_key);

    vscf_impl_destroy(&key_alg);
    vscf_raw_public_key_destroy(&raw_public_key);

    return len;
}

//
//  Export given public key to the PKCS#8 DER format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_key_provider_export_public_key(vscf_key_provider_t *self, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_asn1_serializer);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(public_key, self->random, &error);
    VSCF_ASSERT_PTR(key_alg);

    vscf_raw_public_key_t *raw_public_key = vscf_key_alg_export_public_key(key_alg, public_key, &error);
    if (vscf_error_has_error(&error)) {
        vscf_impl_destroy(&key_alg);
        return vscf_error_status(&error);
    }

    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_key_serializer_serialized_public_key_len(self->key_asn1_serializer, raw_public_key));
    vscf_status_t status = vscf_key_serializer_serialize_public_key(self->key_asn1_serializer, raw_public_key, out);

    vscf_impl_destroy(&key_alg);
    vscf_raw_public_key_destroy(&raw_public_key);

    return status;
}

//
//  Calculate buffer size enough to hold exported private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_provider_exported_private_key_len(vscf_key_provider_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_asn1_serializer);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(private_key, self->random, &error);
    VSCF_ASSERT_PTR(key_alg);

    vscf_raw_private_key_t *raw_private_key = vscf_key_alg_export_private_key(key_alg, private_key, &error);
    if (vscf_error_has_error(&error)) {
        vscf_impl_destroy(&key_alg);
        return vscf_error_status(&error);
    }

    const size_t len = vscf_key_serializer_serialized_private_key_len(self->key_asn1_serializer, raw_private_key);

    vscf_impl_destroy(&key_alg);
    vscf_raw_private_key_destroy(&raw_private_key);

    return len;
}

//
//  Export given private key to the PKCS#8 or SEC1 DER format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_key_provider_export_private_key(vscf_key_provider_t *self, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_asn1_serializer);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(private_key, self->random, &error);
    VSCF_ASSERT_PTR(key_alg);

    vscf_raw_private_key_t *raw_private_key = vscf_key_alg_export_private_key(key_alg, private_key, &error);
    if (vscf_error_has_error(&error)) {
        vscf_impl_destroy(&key_alg);
        return vscf_error_status(&error);
    }

    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_key_serializer_serialized_private_key_len(self->key_asn1_serializer, raw_private_key));
    vscf_status_t status = vscf_key_serializer_serialize_private_key(self->key_asn1_serializer, raw_private_key, out);

    vscf_impl_destroy(&key_alg);
    vscf_raw_private_key_destroy(&raw_private_key);

    return status;
}
