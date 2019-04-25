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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_keys.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_keys_defs.h"

#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <ed25519/ed25519.h>

// clang-format on
//  @end


// clang-format off

// VIRGIL_RATCHET_KDF_ROOT_INFO
static const uint8_t ratchet_kdf_root_info[] = {
        0x56, 0x49, 0x52, 0x47, 0x49, 0x4c, 0x5f, 0x52,
        0x41, 0x54, 0x43, 0x48, 0x45, 0x54, 0x5f, 0x4b,
        0x44, 0x46, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f,
        0x49, 0x4e, 0x46, 0x4f
};

// VIRGIL_RATCHET_KDF_RATCHET_INFO
static const uint8_t ratchet_kdf_ratchet_info[] = {
        0xc5, 0x64, 0x95, 0x24, 0x74, 0x94, 0xc5, 0xf5,
        0x24, 0x15, 0x44, 0x34, 0x84, 0x55, 0x45, 0xf4,
        0xb4, 0x44, 0x65, 0xf5, 0x24, 0x15, 0x44, 0x34,
        0x84, 0x55, 0x45, 0xf4, 0x94, 0xe4, 0x64
};

// clang-format on


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_keys_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_keys_init_ctx(vscr_ratchet_keys_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_keys_cleanup_ctx(vscr_ratchet_keys_t *self);

static const uint8_t ratchet_chain_key_seed[] = {
    0x02
};

static const uint8_t ratchet_message_key_seed[] = {
    0x01
};

//
//  Return size of 'vscr_ratchet_keys_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_keys_ctx_size(void) {

    return sizeof(vscr_ratchet_keys_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_keys_init(vscr_ratchet_keys_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_keys_t));

    self->refcnt = 1;

    vscr_ratchet_keys_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_keys_cleanup(vscr_ratchet_keys_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_keys_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_keys_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_keys_t *
vscr_ratchet_keys_new(void) {

    vscr_ratchet_keys_t *self = (vscr_ratchet_keys_t *) vscr_alloc(sizeof (vscr_ratchet_keys_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_keys_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_keys_delete(vscr_ratchet_keys_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_keys_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_keys_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_keys_destroy(vscr_ratchet_keys_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_keys_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_keys_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_keys_t *
vscr_ratchet_keys_shallow_copy(vscr_ratchet_keys_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_keys_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_keys_init_ctx(vscr_ratchet_keys_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_keys_cleanup_ctx(vscr_ratchet_keys_t *self) {

    VSCR_ASSERT_PTR(self);
}

VSCR_PUBLIC void
vscr_ratchet_keys_derive_initial_keys(
        vsc_data_t shared_secret, vscr_ratchet_symmetric_key_t root_key, vscr_ratchet_symmetric_key_t chain_key) {

    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);

    byte derived_secret[2 * vscr_ratchet_common_hidden_KEY_LEN];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    vscf_hkdf_set_info(hkdf, vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info)));

    vscf_hkdf_derive(hkdf, shared_secret, sizeof(derived_secret), &buffer);
    vscf_hkdf_destroy(&hkdf);

    vsc_buffer_delete(&buffer);

    memcpy(root_key, derived_secret, vscr_ratchet_common_hidden_KEY_LEN);
    memcpy(chain_key, derived_secret + vscr_ratchet_common_hidden_KEY_LEN, vscr_ratchet_common_hidden_KEY_LEN);

    vscr_zeroize(derived_secret, sizeof(derived_secret));
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_keys_create_chain_key(const vscr_ratchet_symmetric_key_t root_key,
        const vscr_ratchet_private_key_t private_key, const vscr_ratchet_public_key_t public_key,
        vscr_ratchet_symmetric_key_t new_root_key, vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(chain_key);

    vscr_status_t status = vscr_status_SUCCESS;

    byte secret[ED25519_DH_LEN];
    int curve_status = curve25519_key_exchange(secret, public_key, private_key);
    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto c_err;
    }

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[2 * vscr_ratchet_common_hidden_KEY_LEN];
    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_reset(hkdf, vsc_data(root_key, vscr_ratchet_common_hidden_KEY_LEN), 0);
    vscf_hkdf_set_info(hkdf, vsc_data(ratchet_kdf_ratchet_info, sizeof(ratchet_kdf_ratchet_info)));
    vscf_hkdf_derive(hkdf, vsc_data(secret, sizeof(secret)), sizeof(derived_secret), &buffer);

    memcpy(new_root_key, derived_secret, vscr_ratchet_common_hidden_KEY_LEN);

    memcpy(chain_key->key, derived_secret + vscr_ratchet_common_hidden_KEY_LEN, vscr_ratchet_common_hidden_KEY_LEN);
    chain_key->index = 0;

    vscf_hkdf_destroy(&hkdf);
    vsc_buffer_delete(&buffer);
    vscr_zeroize(derived_secret, sizeof(derived_secret));

c_err:
    vscr_zeroize(secret, sizeof(secret));

    return status;
}

VSCR_PUBLIC void
vscr_ratchet_keys_advance_chain_key(vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(chain_key);

    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha512_impl(vscf_sha512_new()));

    size_t digest_len = vscf_hmac_digest_len(hmac);

    VSCR_ASSERT(digest_len >= sizeof(chain_key->key));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(digest_len);
    vsc_buffer_make_secure(buffer);

    vscf_hmac_mac(hmac, vsc_data(chain_key->key, sizeof(chain_key->key)),
            vsc_data(ratchet_chain_key_seed, sizeof(ratchet_chain_key_seed)), buffer);

    memcpy(chain_key->key, vsc_buffer_bytes(buffer), sizeof(chain_key->key));
    chain_key->index += 1;

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&buffer);
}

VSCR_PUBLIC vscr_ratchet_message_key_t *
vscr_ratchet_keys_create_message_key(const vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(chain_key);

    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha512_impl(vscf_sha512_new()));

    size_t digest_len = vscf_hmac_digest_len(hmac);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(digest_len);
    vsc_buffer_make_secure(buffer);

    vscf_hmac_mac(hmac, vsc_data(chain_key->key, sizeof(chain_key->key)),
            vsc_data(ratchet_message_key_seed, sizeof(ratchet_message_key_seed)), buffer);

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_message_key_new();

    VSCR_ASSERT(digest_len >= sizeof(message_key->key));

    memcpy(message_key->key, vsc_buffer_bytes(buffer), sizeof(message_key->key));

    message_key->index = chain_key->index;

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&buffer);

    return message_key;
}
