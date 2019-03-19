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
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_rsa_public_key.h"
#include "vscf_rsa_private_key.h"
#include "vscf_ed25519_public_key.h"
#include "vscf_ed25519_private_key.h"
#include "vscf_curve25519_public_key.h"
#include "vscf_curve25519_private_key.h"
#include "vscf_pkcs8_der_deserializer.h"

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

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_key_provider_cleanup_ctx(self);

        vscf_key_provider_release_random(self);
        vscf_key_provider_release_ecies(self);

        vscf_zeroize(self, sizeof(vscf_key_provider_t));
    }
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
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_key_provider_delete(vscf_key_provider_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_key_provider_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
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

    ++self->refcnt;

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
    VSCF_ASSERT_PTR(self->random == NULL);

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

//
//  Setup dependency to the class 'ecies' with shared ownership.
//
VSCF_PUBLIC void
vscf_key_provider_use_ecies(vscf_key_provider_t *self, vscf_ecies_t *ecies) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ecies);
    VSCF_ASSERT(self->ecies == NULL);

    self->ecies = vscf_ecies_shallow_copy(ecies);
}

//
//  Setup dependency to the class 'ecies' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_key_provider_take_ecies(vscf_key_provider_t *self, vscf_ecies_t *ecies) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ecies);
    VSCF_ASSERT_PTR(self->ecies == NULL);

    self->ecies = ecies;
}

//
//  Release dependency to the class 'ecies'.
//
VSCF_PUBLIC void
vscf_key_provider_release_ecies(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ecies_destroy(&self->ecies);
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

    self->rsa_bitlen = 4096;
    self->rsa_exponent = 65537;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_provider_cleanup_ctx(vscf_key_provider_t *self) {

    VSCF_ASSERT_PTR(self);
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

    if (NULL == self->ecies) {
        vscf_ecies_t *ecies = vscf_ecies_new();
        vscf_ecies_use_random(ecies, self->random);
        vscf_status_t status = vscf_ecies_setup_defaults(ecies);
        if (status != vscf_status_SUCCESS) {
            vscf_ecies_destroy(&ecies);
            return status;
        }
        self->ecies = ecies;
    }

    return vscf_status_SUCCESS;
}

//
//  Setup parameters that is used during RSA key generation.
//
VSCF_PUBLIC void
vscf_key_provider_set_rsa_params(vscf_key_provider_t *self, size_t bitlen, size_t exponent) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(bitlen >= 128 && bitlen <= 16384);
    VSCF_ASSERT(bitlen % 2 == 0);
    VSCF_ASSERT(exponent >= 3 && exponent <= 65537);

    self->rsa_bitlen = bitlen;
    self->rsa_exponent = exponent;
}

//
//  Generate new private key from the given id.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_private_key(vscf_key_provider_t *self, vscf_alg_id_t alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vscf_status_t status = vscf_status_SUCCESS;
    vscf_impl_t *key = NULL;

    switch (alg_id) {
    case vscf_alg_id_RSA: {
        vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();
        key = vscf_rsa_private_key_impl(private_key);
        vscf_rsa_private_key_use_random(private_key, self->random);
        vscf_rsa_private_key_set_keygen_params(private_key, self->rsa_bitlen, self->rsa_exponent);

        status = vscf_rsa_private_key_setup_defaults(private_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        status = vscf_rsa_private_key_generate_key(private_key);
        break;
    }

    case vscf_alg_id_ED25519: {
        VSCF_ASSERT_PTR(self->ecies);
        vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();
        key = vscf_ed25519_private_key_impl(private_key);
        vscf_ed25519_private_key_use_random(private_key, self->random);

        status = vscf_ed25519_private_key_setup_defaults(private_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        status = vscf_ed25519_private_key_generate_key(private_key);
        break;
    }

    case vscf_alg_id_CURVE25519: {
        VSCF_ASSERT_PTR(self->ecies);
        vscf_curve25519_private_key_t *private_key = vscf_curve25519_private_key_new();
        key = vscf_curve25519_private_key_impl(private_key);
        vscf_curve25519_private_key_use_random(private_key, self->random);

        status = vscf_curve25519_private_key_setup_defaults(private_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        status = vscf_curve25519_private_key_generate_key(private_key);
        break;
    }

    default:
        VSCF_ASSERT(0 && "Unhandled algorithm identifier.");
        status = vscf_status_ERROR_KEY_GENERATION_FAILED;
        break;
    }

    if ((key != NULL) && (status == vscf_status_SUCCESS)) {
        return key;
    }

    vscf_impl_destroy(&key);
    VSCF_ERROR_SAFE_UPDATE(error, status);
    return NULL;
}

//
//  Import private key from the PKCS#8 format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_import_private_key(vscf_key_provider_t *self, vsc_data_t pkcs8_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(vsc_data_is_valid(pkcs8_data));

    // FIXME: Add error handling

    vscf_pkcs8_der_deserializer_t *deserializer = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(deserializer);

    vscf_raw_key_t *raw_key = vscf_pkcs8_der_deserializer_deserialize_private_key(deserializer, pkcs8_data, error);
    vscf_pkcs8_der_deserializer_destroy(&deserializer);

    if (raw_key == NULL) {
        return NULL;
    }

    vscf_status_t status = vscf_status_SUCCESS;
    vscf_impl_t *private_key = NULL;

    switch (vscf_raw_key_alg_id(raw_key)) {
    case vscf_alg_id_RSA: {
        vscf_rsa_private_key_t *rsa_private_key = vscf_rsa_private_key_new();
        vscf_rsa_private_key_use_random(rsa_private_key, self->random);
        vscf_rsa_private_key_set_keygen_params(rsa_private_key, self->rsa_bitlen, self->rsa_exponent);
        status = vscf_rsa_private_key_setup_defaults(rsa_private_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        private_key = vscf_rsa_private_key_impl(rsa_private_key);
        break;
    }

    case vscf_alg_id_ED25519: {
        VSCF_ASSERT_PTR(self->ecies);
        vscf_ed25519_private_key_t *ed25519_private_key = vscf_ed25519_private_key_new();
        vscf_ed25519_private_key_use_random(ed25519_private_key, self->random);
        status = vscf_ed25519_private_key_setup_defaults(ed25519_private_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        private_key = vscf_ed25519_private_key_impl(ed25519_private_key);
        break;
    }

    case vscf_alg_id_CURVE25519: {
        VSCF_ASSERT_PTR(self->ecies);
        vscf_curve25519_private_key_t *curve25519_private_key = vscf_curve25519_private_key_new();
        vscf_curve25519_private_key_use_random(curve25519_private_key, self->random);
        status = vscf_curve25519_private_key_setup_defaults(curve25519_private_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        private_key = vscf_curve25519_private_key_impl(curve25519_private_key);
        break;
    }

    default:
        status = vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
        break;
    }

    if (private_key == NULL) {
        vscf_raw_key_destroy(&raw_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    status = vscf_private_key_import_private_key(private_key, vscf_raw_key_data(raw_key));
    vscf_raw_key_destroy(&raw_key);

    if (status == vscf_status_SUCCESS) {
        return private_key;
    } else {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        vscf_impl_destroy(&private_key);
        return NULL;
    }
}

//
//  Import public key from the PKCS#8 format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_import_public_key(vscf_key_provider_t *self, vsc_data_t pkcs8_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(vsc_data_is_valid(pkcs8_data));

    vscf_pkcs8_der_deserializer_t *deserializer = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(deserializer);

    vscf_raw_key_t *raw_key = vscf_pkcs8_der_deserializer_deserialize_public_key(deserializer, pkcs8_data, error);
    vscf_pkcs8_der_deserializer_destroy(&deserializer);

    if (raw_key == NULL) {
        return NULL;
    }

    vscf_impl_t *public_key = NULL;
    vscf_status_t status = vscf_status_SUCCESS;

    switch (vscf_raw_key_alg_id(raw_key)) {
    case vscf_alg_id_RSA: {
        vscf_rsa_public_key_t *rsa_public_key = vscf_rsa_public_key_new();
        vscf_rsa_public_key_use_random(rsa_public_key, self->random);
        status = vscf_rsa_public_key_setup_defaults(rsa_public_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        public_key = vscf_rsa_public_key_impl(rsa_public_key);
        break;
    }

    case vscf_alg_id_ED25519: {
        VSCF_ASSERT_PTR(self->ecies);
        vscf_ed25519_public_key_t *ed25519_public_key = vscf_ed25519_public_key_new();
        vscf_ed25519_public_key_use_random(ed25519_public_key, self->random);
        status = vscf_ed25519_public_key_setup_defaults(ed25519_public_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        public_key = vscf_ed25519_public_key_impl(ed25519_public_key);
        break;
    }

    case vscf_alg_id_CURVE25519: {
        VSCF_ASSERT_PTR(self->ecies);
        vscf_curve25519_public_key_t *curve25519_public_key = vscf_curve25519_public_key_new();
        vscf_curve25519_public_key_use_random(curve25519_public_key, self->random);
        status = vscf_curve25519_public_key_setup_defaults(curve25519_public_key);
        if (status != vscf_status_SUCCESS) {
            break;
        }

        public_key = vscf_curve25519_public_key_impl(curve25519_public_key);
        break;
    }

    default:
        status = vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
        break;
    }

    if (public_key == NULL) {
        vscf_raw_key_destroy(&raw_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    status = vscf_public_key_import_public_key(public_key, vscf_raw_key_data(raw_key));
    vscf_raw_key_destroy(&raw_key);

    if (status == vscf_status_SUCCESS) {
        return public_key;
    } else {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        vscf_impl_destroy(&public_key);
        return NULL;
    }
}
