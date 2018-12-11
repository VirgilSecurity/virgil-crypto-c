//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_rng.h"
#include "vscr_ratchet_defs.h"
#include "vscr_ratchet_receiver_chain.h"
#include "vscr_ratchet_skipped_message_key.h"

#include <virgil/crypto/foundation/vscf_asn1wr.h>
#include <virgil/crypto/foundation/vscf_asn1rd.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <ed25519/ed25519.h>

// clang-format on
//  @end


static const uint8_t ratchet_kdf_root_info[] = {
        "VIRGIL_RATCHET_KDF_ROOT_INFO"
};

static const uint8_t ratchet_kdf_ratchet_info[] = {
        "VIRGIL_RATCHET_KDF_RATCHET_INFO"
};


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_init_ctx(vscr_ratchet_t *ratchet_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cleanup_ctx(vscr_ratchet_t *ratchet_ctx);

static vscr_error_t
vscr_ratchet_create_chain_key(const vscr_ratchet_t *ratchet_ctx, const vsc_buffer_t *private_key,
        const vsc_buffer_t *public_key, byte new_root_key[vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH],
        vscr_ratchet_chain_key_t *chain_key);

static void
vscr_ratchet_advance_chain_key(vscr_ratchet_chain_key_t *chain_key);

static vscr_ratchet_message_key_t *
vscr_ratchet_create_message_key(const vscr_ratchet_chain_key_t *chain_key);

static vscr_error_t
vscr_ratchet_decrypt_for_existing_chain(vscr_ratchet_t *ratchet_ctx, const vscr_ratchet_chain_key_t *chain_key,
        RegularMessage message, vsc_buffer_t *buffer);

static vscr_error_t
vscr_ratchet_decrypt_for_new_chain(vscr_ratchet_t *ratchet_ctx, RegularMessage message,
        vsc_buffer_t *buffer);

static vscr_ratchet_receiver_chain_t *
vscr_ratchet_find_receiver_chain(vscr_ratchet_t *ratchet_ctx, RegularMessage message);

static vscr_ratchet_skipped_message_key_t *
vscr_ratchet_find_skipped_message_key(vscr_ratchet_t *ratchet_ctx, RegularMessage message);

static void
vscr_ratchet_erase_skipped_message_key(vscr_ratchet_t *ratchet_ctx,
        vscr_ratchet_skipped_message_key_t *skipped_message_key);

static void
vscr_ratchet_add_receiver_chain(vscr_ratchet_t *ratchet_ctx, vscr_ratchet_receiver_chain_t *receiver_chain);

static void
vscr_ratchet_add_skipped_message_key(vscr_ratchet_t *ratchet_ctx,
        vscr_ratchet_skipped_message_key_t *skipped_message_key);

static const uint8_t ratchet_chain_key_seed[] = {
    0x02
};

static const uint8_t ratchet_message_key_seed[] = {
    0x01
};

//
//  Return size of 'vscr_ratchet_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_ctx_size(void) {

    return sizeof(vscr_ratchet_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_init(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vscr_zeroize(ratchet_ctx, sizeof(vscr_ratchet_t));

    ratchet_ctx->refcnt = 1;

    vscr_ratchet_init_ctx(ratchet_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_cleanup(vscr_ratchet_t *ratchet_ctx) {

    if (ratchet_ctx == NULL) {
        return;
    }

    if (ratchet_ctx->refcnt == 0) {
        return;
    }

    if (--ratchet_ctx->refcnt == 0) {
        vscr_ratchet_cleanup_ctx(ratchet_ctx);

        vscr_ratchet_release_rng(ratchet_ctx);
        vscr_ratchet_release_cipher(ratchet_ctx);

        vscr_zeroize(ratchet_ctx, sizeof(vscr_ratchet_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_new(void) {

    vscr_ratchet_t *ratchet_ctx = (vscr_ratchet_t *) vscr_alloc(sizeof (vscr_ratchet_t));
    VSCR_ASSERT_ALLOC(ratchet_ctx);

    vscr_ratchet_init(ratchet_ctx);

    ratchet_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_delete(vscr_ratchet_t *ratchet_ctx) {

    if (ratchet_ctx == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_ctx->self_dealloc_cb;

    vscr_ratchet_cleanup(ratchet_ctx);

    if (ratchet_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_destroy(vscr_ratchet_t **ratchet_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_ctx_ref);

    vscr_ratchet_t *ratchet_ctx = *ratchet_ctx_ref;
    *ratchet_ctx_ref = NULL;

    vscr_ratchet_delete(ratchet_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_copy(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    ++ratchet_ctx->refcnt;

    return ratchet_ctx;
}

//
//  Setup dependency to the interface 'ratchet rng' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_use_rng(vscr_ratchet_t *ratchet_ctx, vscr_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_ctx->rng == NULL);

    VSCR_ASSERT(vscr_ratchet_rng_is_implemented(rng));

    ratchet_ctx->rng = vscr_impl_copy(rng);
}

//
//  Setup dependency to the interface 'ratchet rng' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_take_rng(vscr_ratchet_t *ratchet_ctx, vscr_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_ctx->rng == NULL);

    VSCR_ASSERT(vscr_ratchet_rng_is_implemented(rng));

    ratchet_ctx->rng = rng;
}

//
//  Release dependency to the interface 'ratchet rng'.
//
VSCR_PUBLIC void
vscr_ratchet_release_rng(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vscr_impl_destroy(&ratchet_ctx->rng);
}

//
//  Setup dependency to the class 'ratchet cipher' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_use_cipher(vscr_ratchet_t *ratchet_ctx, vscr_ratchet_cipher_t *cipher) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(cipher);
    VSCR_ASSERT_PTR(ratchet_ctx->cipher == NULL);

    ratchet_ctx->cipher = vscr_ratchet_cipher_copy(cipher);
}

//
//  Setup dependency to the class 'ratchet cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_take_cipher(vscr_ratchet_t *ratchet_ctx, vscr_ratchet_cipher_t *cipher) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(cipher);
    VSCR_ASSERT_PTR(ratchet_ctx->cipher == NULL);

    ratchet_ctx->cipher = cipher;
}

//
//  Release dependency to the class 'ratchet cipher'.
//
VSCR_PUBLIC void
vscr_ratchet_release_cipher(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vscr_ratchet_cipher_destroy(&ratchet_ctx->cipher);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_init_ctx(vscr_ratchet_t *ratchet_ctx) {

    VSCR_UNUSED(ratchet_ctx);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cleanup_ctx(vscr_ratchet_t *ratchet_ctx) {

    vscr_ratchet_sender_chain_destroy(&ratchet_ctx->sender_chain);
    vscr_ratchet_receiver_chain_list_node_destroy(&ratchet_ctx->receiver_chains);
    vscr_ratchet_skipped_message_key_list_node_destroy(&ratchet_ctx->skipped_message_keys);
}

static vscr_error_t
vscr_ratchet_create_chain_key(const vscr_ratchet_t *ratchet_ctx, const vsc_buffer_t *private_key,
        const vsc_buffer_t *public_key, byte new_root_key[vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH],
        vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(private_key);
    VSCR_ASSERT_PTR(public_key);
    VSCR_ASSERT_PTR(chain_key);

    vsc_buffer_t *secret = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    vsc_buffer_make_secure(secret);

    if (curve25519_key_exchange(vsc_buffer_ptr(secret), vsc_buffer_bytes(public_key), vsc_buffer_bytes(private_key)) !=
            0) {
        vsc_buffer_destroy(&secret);

        return vscr_CURVE25519_ERROR;
    }

    vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *derived_secret = vsc_buffer_new_with_capacity(2 * vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);
    vsc_buffer_make_secure(derived_secret);
    vscf_hkdf_derive(hkdf, vsc_buffer_data(secret), vsc_data(ratchet_ctx->root_key, sizeof(ratchet_ctx->root_key)),
            vsc_data(ratchet_kdf_ratchet_info, sizeof(ratchet_kdf_ratchet_info)),
            derived_secret, vsc_buffer_capacity(derived_secret));

    memcpy(new_root_key, vsc_buffer_bytes(derived_secret), vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);

    memcpy(chain_key->key, vsc_buffer_bytes(derived_secret) + vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH,
            vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);
    chain_key->index = 0;

    vscf_hkdf_destroy(&hkdf);
    vsc_buffer_destroy(&secret);
    vsc_buffer_destroy(&derived_secret);

    return vscr_SUCCESS;
}

static void
vscr_ratchet_advance_chain_key(vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(chain_key);

    vsc_buffer_t *buffer = vsc_buffer_new();
    vsc_buffer_use(buffer, chain_key->key, sizeof(chain_key->key));

    vscf_hmac_impl_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(vscf_sha256_new()));
    vscf_hmac_mac(hmac, vsc_data(chain_key->key, sizeof(chain_key->key)),
            vsc_data(ratchet_chain_key_seed, sizeof(ratchet_chain_key_seed)), buffer);

    chain_key->index += 1;

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&buffer);
}

static vscr_ratchet_message_key_t *
vscr_ratchet_create_message_key(const vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(chain_key);

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_message_key_new();

    vsc_buffer_t *buffer = vsc_buffer_new();
    vsc_buffer_use(buffer, message_key->key, sizeof(message_key->key));
    vscf_hmac_impl_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(vscf_sha256_new()));
    vscf_hmac_mac(hmac, vsc_data(chain_key->key, sizeof(chain_key->key)),
            vsc_data(ratchet_message_key_seed, sizeof(ratchet_message_key_seed)), buffer);

    message_key->index = chain_key->index;

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&buffer);

    return message_key;
}

static vscr_error_t
vscr_ratchet_decrypt_for_existing_chain(vscr_ratchet_t *ratchet_ctx, const vscr_ratchet_chain_key_t *chain_key,
        const RegularMessage message, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(chain_key);
    VSCR_ASSERT_PTR(buffer);

    // This message should be already decrypted
    if (message.counter < chain_key->index) {
        return vscr_BAD_MESSAGE;
    }

    // Too many lost messages
    if (message.counter - chain_key->index > vscr_ratchet_common_MAX_MESSAGE_GAP) {
        return vscr_BAD_MESSAGE;
    }

    vscr_ratchet_chain_key_t *new_chain_key = vscr_ratchet_chain_key_new();
    vscr_ratchet_chain_key_clone(chain_key, new_chain_key);

    while (new_chain_key->index < message.counter) {
        vscr_ratchet_advance_chain_key(new_chain_key);
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_create_message_key(new_chain_key);

    vscr_error_t result = vscr_ratchet_cipher_decrypt(ratchet_ctx->cipher,
            vsc_data(message_key->key, sizeof(message_key->key)),
            vsc_data(message.cipher_text.bytes,message.cipher_text.size),
            buffer);

    vscr_ratchet_chain_key_destroy(&new_chain_key);
    vscr_ratchet_message_key_destroy(&message_key);

    return result;
}

static vscr_error_t
vscr_ratchet_decrypt_for_new_chain(vscr_ratchet_t *ratchet_ctx, const RegularMessage message,
        vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(buffer);

    if (!ratchet_ctx->sender_chain) {
        return vscr_BAD_MESSAGE;
    }

    if (message.counter > vscr_ratchet_common_MAX_MESSAGE_GAP) {
        return vscr_BAD_MESSAGE;
    }

    byte new_root_key[vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH];
    vsc_buffer_t *public_key = vsc_buffer_new_with_data(vsc_data(message.public_key, sizeof(message.public_key)));
    vscr_ratchet_receiver_chain_t *new_chain = vscr_ratchet_receiver_chain_new();
    vscr_error_t result = vscr_ratchet_create_chain_key(ratchet_ctx, ratchet_ctx->sender_chain->private_key,
                                                        public_key, new_root_key, &new_chain->chain_key);

    if (result != vscr_SUCCESS) {
        vscr_ratchet_receiver_chain_destroy(&new_chain);
        vscr_zeroize(new_root_key, vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);

        return result;
    }

    result = vscr_ratchet_decrypt_for_existing_chain(ratchet_ctx, &new_chain->chain_key, message, buffer);

    vscr_ratchet_receiver_chain_destroy(&new_chain);
    vscr_zeroize(new_root_key, vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);

    return result;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_respond(vscr_ratchet_t *ratchet_ctx, vsc_data_t shared_secret, vsc_buffer_t *ratchet_public_key,
        const RegularMessage message) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(ratchet_public_key);
    VSCR_ASSERT(vsc_buffer_len(ratchet_public_key) == ED25519_KEY_LEN);
    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);

    VSCR_ASSERT(!ratchet_ctx->receiver_chains);

    vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *derived_secret = vsc_buffer_new_with_capacity(2 * vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);
    vsc_buffer_make_secure(derived_secret);
    vscf_hkdf_derive(hkdf, shared_secret, vsc_data_empty(), vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info)),
            derived_secret, vsc_buffer_capacity(derived_secret));
    vscf_hkdf_destroy(&hkdf);

    memcpy(ratchet_ctx->root_key, vsc_buffer_bytes(derived_secret), vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);

    vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_receiver_chain_new();
    receiver_chain->chain_key.index = 0;
    memcpy(receiver_chain->chain_key.key,
            vsc_buffer_bytes(derived_secret) + vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH,
            vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);
    receiver_chain->public_key = vsc_buffer_copy(ratchet_public_key);

    vscr_ratchet_add_receiver_chain(ratchet_ctx, receiver_chain);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vscr_ratchet_decrypt_len(ratchet_ctx, message.cipher_text.size));
    vsc_buffer_make_secure(buffer);
    vscr_error_t status = vscr_ratchet_decrypt_for_existing_chain(ratchet_ctx, &receiver_chain->chain_key, message, buffer);
    vsc_buffer_destroy(&buffer);

    vscr_ratchet_receiver_chain_destroy(&receiver_chain);
    vsc_buffer_destroy(&derived_secret);

    return status;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_initiate(vscr_ratchet_t *ratchet_ctx, vsc_data_t shared_secret, vsc_buffer_t *ratchet_private_key) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(ratchet_private_key);
    VSCR_ASSERT(vsc_buffer_len(ratchet_private_key) == ED25519_KEY_LEN);
    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);

    VSCR_ASSERT_PTR(!ratchet_ctx->sender_chain);

    vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *derived_secret = vsc_buffer_new_with_capacity(2 * vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);
    vsc_buffer_make_secure(derived_secret);
    vscf_hkdf_derive(hkdf, shared_secret, vsc_data_empty(), vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info)),
            derived_secret, vsc_buffer_capacity(derived_secret));
    vscf_hkdf_destroy(&hkdf);

    memcpy(ratchet_ctx->root_key, vsc_buffer_bytes(derived_secret), vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);

    vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();
    ratchet_ctx->sender_chain = sender_chain;
    sender_chain->private_key = vsc_buffer_copy(ratchet_private_key);
    sender_chain->chain_key.index = 0;
    memcpy(sender_chain->chain_key.key,
            vsc_buffer_bytes(derived_secret) + vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH,
            vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH);

    // TODO: Optimize
    vsc_buffer_t *ratchet_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);

    if (curve25519_get_pubkey(vsc_buffer_ptr(ratchet_public_key), vsc_buffer_bytes(ratchet_private_key)) != 0) {
        vsc_buffer_destroy(&derived_secret);
        vsc_buffer_destroy(&ratchet_public_key);

        return vscr_CURVE25519_ERROR;
    }

    vsc_buffer_reserve(ratchet_public_key, ED25519_KEY_LEN);
    sender_chain->public_key = ratchet_public_key;

    vsc_buffer_destroy(&derived_secret);

    return vscr_SUCCESS;
}

VSCR_PUBLIC size_t
vscr_ratchet_encrypt_len(vscr_ratchet_t *ratchet_ctx, size_t plain_text_len) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    //  RATCHETRegularMessage ::= SEQUENCE {
    //       version INTEGER,
    //       counter INTEGER,
    //       public_key OCTET_STRING,
    //       cipher_text OCTET_STRING }

    size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                              + 1 + 1 + 5 /* INTEGER */
                              + 1 + 1 + 5 /* INTEGER */
                              + 1 + 1 + 32 /* public_key */
                              + 1 + 3 + vscr_ratchet_cipher_encrypt_len(ratchet_ctx->cipher, plain_text_len); /* cipher_text */

    return top_sequence_len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_encrypt(vscr_ratchet_t *ratchet_ctx, vsc_data_t plain_text, RegularMessage *regular_message) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vscr_error_t result = vscr_SUCCESS;

    if (!ratchet_ctx->sender_chain) {
        vsc_buffer_t *ratchet_private_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
        vsc_buffer_make_secure(ratchet_private_key);
        // FIXME
        vscr_ratchet_rng_generate_random_data(ratchet_ctx->rng, ED25519_KEY_LEN, ratchet_private_key);
        vsc_buffer_t *ratchet_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
        result = curve25519_get_pubkey(vsc_buffer_ptr(ratchet_public_key), vsc_buffer_bytes(ratchet_private_key)) == 0
                         ? vscr_SUCCESS
                         : vscr_CURVE25519_ERROR;
        vsc_buffer_reserve(ratchet_public_key, ED25519_KEY_LEN);

        vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();
        sender_chain->private_key = ratchet_private_key;
        sender_chain->public_key = ratchet_public_key;

        ratchet_ctx->sender_chain = sender_chain;

        if (result != vscr_SUCCESS) {
            return result;
        }

        result = vscr_ratchet_create_chain_key(ratchet_ctx, sender_chain->private_key,
                ratchet_ctx->receiver_chains->value->public_key, ratchet_ctx->root_key, &sender_chain->chain_key);
    }

    if (result != vscr_SUCCESS) {
        return result;
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_create_message_key(&ratchet_ctx->sender_chain->chain_key);

    vscr_ratchet_advance_chain_key(&ratchet_ctx->sender_chain->chain_key);

    vsc_buffer_t *buffer =
            vsc_buffer_new_with_capacity(vscr_ratchet_cipher_encrypt_len(ratchet_ctx->cipher, plain_text.len));
    result = vscr_ratchet_cipher_encrypt(
            ratchet_ctx->cipher, vsc_data(message_key->key, sizeof(message_key->key)), plain_text, buffer);

    if (result != vscr_SUCCESS) {
        vscr_ratchet_message_key_destroy(&message_key);
        vsc_buffer_destroy(&buffer);
        return result;
    }

    regular_message->version = vscr_ratchet_common_RATCHET_REGULAR_MESSAGE_VERSION;
    regular_message->counter = message_key->index;

    memcpy(regular_message->public_key, ratchet_ctx->sender_chain->public_key->bytes, ratchet_ctx->sender_chain->public_key->len);

    memcpy(regular_message->cipher_text.bytes, buffer->bytes, buffer->len);
    regular_message->cipher_text.size += buffer->len;

    vscr_ratchet_message_key_destroy(&message_key);
    vsc_buffer_destroy(&buffer);

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_decrypt_len(vscr_ratchet_t *ratchet_ctx, size_t cipher_text_len) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    // TODO: Optimize, real cipher text length is smaller
    return vscr_ratchet_cipher_decrypt_len(ratchet_ctx->cipher, cipher_text_len);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_decrypt(vscr_ratchet_t *ratchet_ctx, RegularMessage *regular_message, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(plain_text);

    if (regular_message->version != vscr_ratchet_common_RATCHET_REGULAR_MESSAGE_VERSION) {
        return vscr_MESSAGE_VERSION_DOESN_T_MATCH;
    }

    vscr_error_t result;

    vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_find_receiver_chain(ratchet_ctx, (*regular_message));

    if (!receiver_chain) {
        result = vscr_ratchet_decrypt_for_new_chain(ratchet_ctx, (*regular_message), plain_text);
    } else if (receiver_chain->chain_key.index > (*regular_message).counter) {
        vscr_ratchet_skipped_message_key_t *skipped_message_key =
                vscr_ratchet_find_skipped_message_key(ratchet_ctx, (*regular_message));

        if (!skipped_message_key) {
            result = vscr_BAD_MESSAGE;
        } else {
            result = vscr_ratchet_cipher_decrypt(ratchet_ctx->cipher,
                    vsc_data(skipped_message_key->message_key->key, sizeof(skipped_message_key->message_key->key)),
                    vsc_data((*regular_message).cipher_text.bytes, (*regular_message).cipher_text.size), plain_text);

            if (result == vscr_SUCCESS) {
                vscr_ratchet_erase_skipped_message_key(ratchet_ctx, skipped_message_key);
            }
        }
    } else {
        result = vscr_ratchet_decrypt_for_existing_chain(ratchet_ctx, &receiver_chain->chain_key,
                (*regular_message), plain_text);
    }

    if (result != vscr_SUCCESS) {
        return result;
    }

    if (!receiver_chain) {
        vscr_ratchet_receiver_chain_t *new_receiver_chain = vscr_ratchet_receiver_chain_new();

        // FIXME
        vsc_buffer_t *buffer = vsc_buffer_new_with_data(vsc_data((*regular_message).public_key,
                sizeof((*regular_message).public_key)));
        new_receiver_chain->public_key = vsc_buffer_copy(buffer);

        // TODO: Optimize
        result = vscr_ratchet_create_chain_key(ratchet_ctx, ratchet_ctx->sender_chain->private_key,
                new_receiver_chain->public_key, ratchet_ctx->root_key, &new_receiver_chain->chain_key);

        vscr_ratchet_add_receiver_chain(ratchet_ctx, new_receiver_chain);

        vscr_ratchet_sender_chain_destroy(&ratchet_ctx->sender_chain);
        receiver_chain = new_receiver_chain;
        vscr_ratchet_receiver_chain_destroy(&new_receiver_chain);
    }

    while (receiver_chain->chain_key.index < (*regular_message).counter) {
        vscr_ratchet_skipped_message_key_t *skipped_message_key = vscr_ratchet_skipped_message_key_new();
        skipped_message_key->message_key = vscr_ratchet_create_message_key(&receiver_chain->chain_key);
        skipped_message_key->public_key = vsc_buffer_copy(receiver_chain->public_key);
        vscr_ratchet_advance_chain_key(&receiver_chain->chain_key);
        vscr_ratchet_add_skipped_message_key(ratchet_ctx, skipped_message_key);
        vscr_ratchet_skipped_message_key_destroy(&skipped_message_key);
    }

    vscr_ratchet_advance_chain_key(&receiver_chain->chain_key);

    return result;
}

static vscr_ratchet_receiver_chain_t *
vscr_ratchet_find_receiver_chain(vscr_ratchet_t *ratchet_ctx, const RegularMessage message) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vscr_ratchet_receiver_chain_list_node_t *chain_list_node = ratchet_ctx->receiver_chains;

    while (chain_list_node) {
        if (!memcmp(message.public_key, vsc_buffer_bytes(chain_list_node->value->public_key),
                    ED25519_KEY_LEN)) {
            return chain_list_node->value;
        }
        chain_list_node = chain_list_node->next;
    }

    return NULL;
}

static vscr_ratchet_skipped_message_key_t *
vscr_ratchet_find_skipped_message_key(vscr_ratchet_t *ratchet_ctx, const RegularMessage message) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node = ratchet_ctx->skipped_message_keys;

    while (skipped_message_key_list_node) {
        if (message.counter == skipped_message_key_list_node->value->message_key->index &&
                !memcmp(message.public_key,
                        vsc_buffer_bytes(skipped_message_key_list_node->value->public_key), ED25519_KEY_LEN)) {
            return skipped_message_key_list_node->value;
        }
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    return NULL;
}

static void
vscr_ratchet_erase_skipped_message_key(vscr_ratchet_t *ratchet_ctx,
        vscr_ratchet_skipped_message_key_t *skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(skipped_message_key);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node_prev = NULL;
    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node = ratchet_ctx->skipped_message_keys;

    while (skipped_message_key_list_node) {
        if (skipped_message_key_list_node->value == skipped_message_key) {
            if (skipped_message_key_list_node_prev) {
                skipped_message_key_list_node_prev->next = skipped_message_key_list_node->next;
            } else {
                ratchet_ctx->skipped_message_keys = skipped_message_key_list_node->next;
            }

            skipped_message_key_list_node->next = NULL;
            vscr_ratchet_skipped_message_key_list_node_destroy(&skipped_message_key_list_node);

            return;
        }

        skipped_message_key_list_node_prev = skipped_message_key_list_node;
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    // Element not found
    VSCR_ASSERT(false);
}

static void
vscr_ratchet_add_receiver_chain(vscr_ratchet_t *ratchet_ctx, vscr_ratchet_receiver_chain_t *receiver_chain) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(receiver_chain);

    vscr_ratchet_receiver_chain_list_node_t *receiver_chain_list_node = vscr_ratchet_receiver_chain_list_node_new();
    receiver_chain_list_node->value = vscr_ratchet_receiver_chain_copy(receiver_chain);
    receiver_chain_list_node->next = ratchet_ctx->receiver_chains;
    ratchet_ctx->receiver_chains = receiver_chain_list_node;

    if (!ratchet_ctx->receiver_chains->next) {
        return;
    }

    size_t chains_count = 2;
    while (receiver_chain_list_node->next->next) {
        chains_count += 1;
        receiver_chain_list_node = receiver_chain_list_node->next;
    }

    VSCR_ASSERT(chains_count <= vscr_ratchet_common_MAX_RECEIVERS_CHAINS);

    if (chains_count == vscr_ratchet_common_MAX_RECEIVERS_CHAINS) {
        vscr_ratchet_receiver_chain_list_node_destroy(&receiver_chain_list_node->next);
    }
}

static void
vscr_ratchet_add_skipped_message_key(vscr_ratchet_t *ratchet_ctx,
        vscr_ratchet_skipped_message_key_t *skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet_ctx);
    VSCR_ASSERT_PTR(skipped_message_key);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node =
            vscr_ratchet_skipped_message_key_list_node_new();
    skipped_message_key_list_node->value = vscr_ratchet_skipped_message_key_copy(skipped_message_key);
    skipped_message_key_list_node->next = ratchet_ctx->skipped_message_keys;

    if (!ratchet_ctx->skipped_message_keys) {
        ratchet_ctx->skipped_message_keys = skipped_message_key_list_node;

        return;
    }

    size_t msgs_count = 2;
    while (skipped_message_key_list_node->next->next) {
        msgs_count += 1;
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    VSCR_ASSERT(msgs_count <= vscr_ratchet_common_MAX_SKIPPED_MESSAGES);

    if (msgs_count == vscr_ratchet_common_MAX_SKIPPED_MESSAGES) {
        vscr_ratchet_skipped_message_key_list_node_destroy(&skipped_message_key_list_node->next);
    }
}

VSCR_PUBLIC size_t
vscr_ratchet_serialize_len(vscr_ratchet_t *ratchet_ctx) {

    VSCR_ASSERT_PTR(ratchet_ctx);

    //  RATCHETRatchet ::= SEQUENCE {
    //       sender chain OCTET_STRING,
    //       receiver chains OCTET_STRING,
    //       skipped message keys OCTET_STRING,
    //       root key OCTET_STRING }

    size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                              + 1 + 1 + 5 /* INTEGER */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 1 + 32; /* KEY */

    return top_sequence_len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_serialize(vscr_ratchet_t *ratchet_ctx, vsc_buffer_t *output) {

    //  TODO: This is STUB. Implement me.
    VSCR_UNUSED(ratchet_ctx);
    VSCR_UNUSED(output);

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    //  TODO: This is STUB. Implement me.
    VSCR_UNUSED(input);
    VSCR_UNUSED(err_ctx);

    return NULL;
}
