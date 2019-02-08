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
//  Utils class for working with keys formats
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_key_utils.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common_hidden.h"

#include <virgil/crypto/foundation/vscf_pkcs8_der_deserializer.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_pkcs8_der_deserializer.h>
#endif

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'ratchet key utils' context.
//
struct vscr_ratchet_key_utils_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    vscf_pkcs8_der_deserializer_t *pkcs8;
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_key_utils_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_key_utils_init_ctx(vscr_ratchet_key_utils_t *ratchet_key_utils);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_key_utils_cleanup_ctx(vscr_ratchet_key_utils_t *ratchet_key_utils);

//
//  Return size of 'vscr_ratchet_key_utils_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_key_utils_ctx_size(void) {

    return sizeof(vscr_ratchet_key_utils_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_init(vscr_ratchet_key_utils_t *ratchet_key_utils) {

    VSCR_ASSERT_PTR(ratchet_key_utils);

    vscr_zeroize(ratchet_key_utils, sizeof(vscr_ratchet_key_utils_t));

    ratchet_key_utils->refcnt = 1;

    vscr_ratchet_key_utils_init_ctx(ratchet_key_utils);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_cleanup(vscr_ratchet_key_utils_t *ratchet_key_utils) {

    if (ratchet_key_utils == NULL) {
        return;
    }

    if (ratchet_key_utils->refcnt == 0) {
        return;
    }

    if (--ratchet_key_utils->refcnt == 0) {
        vscr_ratchet_key_utils_cleanup_ctx(ratchet_key_utils);

        vscr_zeroize(ratchet_key_utils, sizeof(vscr_ratchet_key_utils_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_key_utils_t *
vscr_ratchet_key_utils_new(void) {

    vscr_ratchet_key_utils_t *ratchet_key_utils = (vscr_ratchet_key_utils_t *) vscr_alloc(sizeof (vscr_ratchet_key_utils_t));
    VSCR_ASSERT_ALLOC(ratchet_key_utils);

    vscr_ratchet_key_utils_init(ratchet_key_utils);

    ratchet_key_utils->self_dealloc_cb = vscr_dealloc;

    return ratchet_key_utils;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_delete(vscr_ratchet_key_utils_t *ratchet_key_utils) {

    if (ratchet_key_utils == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_key_utils->self_dealloc_cb;

    vscr_ratchet_key_utils_cleanup(ratchet_key_utils);

    if (ratchet_key_utils->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_key_utils);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_key_utils_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_destroy(vscr_ratchet_key_utils_t **ratchet_key_utils_ref) {

    VSCR_ASSERT_PTR(ratchet_key_utils_ref);

    vscr_ratchet_key_utils_t *ratchet_key_utils = *ratchet_key_utils_ref;
    *ratchet_key_utils_ref = NULL;

    vscr_ratchet_key_utils_delete(ratchet_key_utils);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_key_utils_t *
vscr_ratchet_key_utils_shallow_copy(vscr_ratchet_key_utils_t *ratchet_key_utils) {

    VSCR_ASSERT_PTR(ratchet_key_utils);

    ++ratchet_key_utils->refcnt;

    return ratchet_key_utils;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_key_utils_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_key_utils_init_ctx(vscr_ratchet_key_utils_t *ratchet_key_utils) {

    VSCR_ASSERT_PTR(ratchet_key_utils);

    ratchet_key_utils->pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(ratchet_key_utils->pkcs8);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_key_utils_cleanup_ctx(vscr_ratchet_key_utils_t *ratchet_key_utils) {

    VSCR_ASSERT_PTR(ratchet_key_utils);

    vscf_pkcs8_der_deserializer_destroy(&ratchet_key_utils->pkcs8);
}

//
//  Computes 8 bytes key pair id from public key
//
VSCR_PUBLIC vscr_error_t
vscr_ratchet_key_utils_compute_public_key_id(
        vscr_ratchet_key_utils_t *ratchet_key_utils, vsc_data_t public_key, vsc_buffer_t *key_id) {

    if (public_key.len == vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH) {
        byte digest[vscf_sha512_DIGEST_LEN];

        vsc_buffer_t digest_buf;
        vsc_buffer_init(&digest_buf);
        vsc_buffer_use(&digest_buf, digest, sizeof(digest));

        vscf_sha512_hash(public_key, &digest_buf);

        vsc_buffer_delete(&digest_buf);

        memcpy(vsc_buffer_unused_bytes(key_id), digest, vscr_ratchet_common_KEY_ID_LEN);
        vsc_buffer_inc_used(key_id, vscr_ratchet_common_KEY_ID_LEN);

        return vscr_SUCCESS;
    }

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vsc_buffer_t *raw_public_key =
            vscr_ratchet_key_utils_extract_ratchet_public_key(ratchet_key_utils, public_key, &error_ctx);

    if (error_ctx.error != vscr_SUCCESS) {
        return error_ctx.error;
    }

    vscr_error_t result =
            vscr_ratchet_key_utils_compute_public_key_id(ratchet_key_utils, vsc_buffer_data(raw_public_key), key_id);

    vsc_buffer_destroy(&raw_public_key);

    return result;
}

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_key_utils_extract_ratchet_public_key(
        vscr_ratchet_key_utils_t *ratchet_key_utils, vsc_data_t data, vscr_error_ctx_t *err_ctx) {

    vscf_error_ctx_t error_ctx;
    vscf_error_ctx_reset(&error_ctx);

    vsc_buffer_t *result = NULL;

    vscf_raw_key_t *raw_key =
            vscf_pkcs8_der_deserializer_deserialize_public_key(ratchet_key_utils->pkcs8, data, &error_ctx);

    if (error_ctx.error != vscf_SUCCESS) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

        goto err;
    }

    if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_X25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH) {
            VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

            goto err;
        }

        result = vsc_buffer_new_with_data(vscf_raw_key_data(raw_key));
    } else if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_ED25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH) {
            VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

            goto err;
        }

        result = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);

        int curve25519_status =
                ed25519_pubkey_to_curve25519(vsc_buffer_unused_bytes(result), vscf_raw_key_data(raw_key).bytes);

        if (curve25519_status != 0) {
            VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_CURVE25519);

            vsc_buffer_destroy(&result);

            goto err;
        }

        vsc_buffer_inc_used(result, vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);
    } else {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_INVALID_KEY_TYPE);

        goto err;
    }

err:
    vscf_raw_key_destroy(&raw_key);

    return result;
}

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_key_utils_extract_ratchet_private_key(
        vscr_ratchet_key_utils_t *ratchet_key_utils, vsc_data_t data, vscr_error_ctx_t *err_ctx) {

    vscf_error_ctx_t error_ctx;
    vscf_error_ctx_reset(&error_ctx);

    vsc_buffer_t *result = NULL;

    vscf_raw_key_t *raw_key =
            vscf_pkcs8_der_deserializer_deserialize_private_key(ratchet_key_utils->pkcs8, data, &error_ctx);

    if (error_ctx.error != vscf_SUCCESS) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

        goto err;
    }

    if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_X25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH + 2) {
            VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_INVALID_KEY_TYPE);

            goto err;
        }

        result = vsc_buffer_new_with_data(
                vsc_data_slice_beg(vscf_raw_key_data(raw_key), 2, vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH));
    } else if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_ED25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH + 2) {
            VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

            goto err;
        }

        result = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);

        int curve25519_status = ed25519_key_to_curve25519(vsc_buffer_unused_bytes(result),
                vsc_data_slice_beg(vscf_raw_key_data(raw_key), 2, vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH).bytes);

        if (curve25519_status != 0) {
            VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_CURVE25519);

            vsc_buffer_destroy(&result);

            goto err;
        }

        vsc_buffer_inc_used(result, vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);
    } else {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_INVALID_KEY_TYPE);

        goto err;
    }

err:
    vscf_raw_key_destroy(&raw_key);

    return result;
}
