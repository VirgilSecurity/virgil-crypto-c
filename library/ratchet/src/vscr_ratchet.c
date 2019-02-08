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

#include "vscr_ratchet.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_message_key.h"
#include "vscr_ratchet_receiver_chain_list_node.h"
#include "vscr_ratchet_receiver_chain.h"
#include "vscr_ratchet_skipped_message_key.h"
#include "vscr_ratchet_sender_chain.h"
#include "vscr_ratchet_skipped_message_key_list_node.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <ed25519/ed25519.h>

// clang-format on
//  @end


static const uint8_t ratchet_kdf_root_info[] = {"VIRGIL_RATCHET_KDF_ROOT_INFO"};

static const uint8_t ratchet_kdf_ratchet_info[] = {"VIRGIL_RATCHET_KDF_RATCHET_INFO"};


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'ratchet' context.
//
struct vscr_ratchet_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;
    //
    //  Dependency to the class 'ratchet cipher'.
    //
    vscr_ratchet_cipher_t *cipher;

    vscr_ratchet_sender_chain_t *sender_chain;

    uint32_t prev_sender_chain_count;

    vscr_ratchet_receiver_chain_list_node_t *receiver_chains;

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_keys;

    byte root_key[vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH];
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_init_ctx(vscr_ratchet_t *ratchet);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cleanup_ctx(vscr_ratchet_t *ratchet);

static vscr_error_t
vscr_ratchet_create_chain_key(const vscr_ratchet_t *ratchet, vsc_data_t private_key, vsc_data_t public_key,
        byte new_root_key[vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH], vscr_ratchet_chain_key_t *chain_key);

static void
vscr_ratchet_advance_chain_key(vscr_ratchet_chain_key_t *chain_key);

static vscr_ratchet_message_key_t *
vscr_ratchet_create_message_key(const vscr_ratchet_chain_key_t *chain_key);

static vscr_error_t
vscr_ratchet_decrypt_for_existing_chain(vscr_ratchet_t *ratchet, const vscr_ratchet_chain_key_t *chain_key,
        const RegularMessage *message, vsc_buffer_t *buffer);

static vscr_error_t
vscr_ratchet_decrypt_for_new_chain(vscr_ratchet_t *ratchet, const RegularMessage *message, vsc_buffer_t *buffer);

static vscr_ratchet_receiver_chain_list_node_t *
vscr_ratchet_find_receiver_chain(vscr_ratchet_t *ratchet, const RegularMessage *message);

static vscr_ratchet_receiver_chain_list_node_t *
vscr_ratchet_add_receiver_chain(vscr_ratchet_t *ratchet, vscr_ratchet_receiver_chain_t *receiver_chain);

static void
vscr_ratchet_delete_next_receiver_chain(vscr_ratchet_receiver_chain_list_node_t *node);

static vscr_ratchet_skipped_message_key_t *
vscr_ratchet_find_skipped_message_key(vscr_ratchet_t *ratchet, const RegularMessage *message);

static void
vscr_ratchet_delete_skipped_message_key(vscr_ratchet_t *ratchet,
        vscr_ratchet_skipped_message_key_t *skipped_message_key);

static void
vscr_ratchet_add_skipped_message_key(vscr_ratchet_t *ratchet, vscr_ratchet_skipped_message_key_t *skipped_message_key);

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
vscr_ratchet_init(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);

    vscr_zeroize(ratchet, sizeof(vscr_ratchet_t));

    ratchet->refcnt = 1;

    vscr_ratchet_init_ctx(ratchet);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_cleanup(vscr_ratchet_t *ratchet) {

    if (ratchet == NULL) {
        return;
    }

    if (ratchet->refcnt == 0) {
        return;
    }

    if (--ratchet->refcnt == 0) {
        vscr_ratchet_cleanup_ctx(ratchet);

        vscr_ratchet_release_rng(ratchet);
        vscr_ratchet_release_cipher(ratchet);

        vscr_zeroize(ratchet, sizeof(vscr_ratchet_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_new(void) {

    vscr_ratchet_t *ratchet = (vscr_ratchet_t *) vscr_alloc(sizeof (vscr_ratchet_t));
    VSCR_ASSERT_ALLOC(ratchet);

    vscr_ratchet_init(ratchet);

    ratchet->self_dealloc_cb = vscr_dealloc;

    return ratchet;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_delete(vscr_ratchet_t *ratchet) {

    if (ratchet == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet->self_dealloc_cb;

    vscr_ratchet_cleanup(ratchet);

    if (ratchet->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_destroy(vscr_ratchet_t **ratchet_ref) {

    VSCR_ASSERT_PTR(ratchet_ref);

    vscr_ratchet_t *ratchet = *ratchet_ref;
    *ratchet_ref = NULL;

    vscr_ratchet_delete(ratchet);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_shallow_copy(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);

    ++ratchet->refcnt;

    return ratchet;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_use_rng(vscr_ratchet_t *ratchet, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    ratchet->rng = vscf_impl_shallow_copy(rng);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_take_rng(vscr_ratchet_t *ratchet, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    ratchet->rng = rng;
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_release_rng(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);

    vscf_impl_destroy(&ratchet->rng);
}

//
//  Setup dependency to the class 'ratchet cipher' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_use_cipher(vscr_ratchet_t *ratchet, vscr_ratchet_cipher_t *cipher) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(cipher);
    VSCR_ASSERT_PTR(ratchet->cipher == NULL);

    ratchet->cipher = vscr_ratchet_cipher_shallow_copy(cipher);
}

//
//  Setup dependency to the class 'ratchet cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_take_cipher(vscr_ratchet_t *ratchet, vscr_ratchet_cipher_t *cipher) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(cipher);
    VSCR_ASSERT_PTR(ratchet->cipher == NULL);

    ratchet->cipher = cipher;
}

//
//  Release dependency to the class 'ratchet cipher'.
//
VSCR_PUBLIC void
vscr_ratchet_release_cipher(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);

    vscr_ratchet_cipher_destroy(&ratchet->cipher);
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
vscr_ratchet_init_ctx(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cleanup_ctx(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);

    vscr_ratchet_sender_chain_destroy(&ratchet->sender_chain);
    vscr_ratchet_receiver_chain_list_node_destroy(&ratchet->receiver_chains);
    vscr_ratchet_skipped_message_key_list_node_destroy(&ratchet->skipped_message_keys);
}

VSCR_PUBLIC void
vscr_ratchet_setup_defaults(vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT(ratchet->rng == NULL);
    VSCR_ASSERT(ratchet->cipher == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    vscr_ratchet_take_rng(ratchet, vscf_ctr_drbg_impl(rng));
    vscr_ratchet_take_cipher(ratchet, vscr_ratchet_cipher_new());
}

static vscr_error_t
vscr_ratchet_create_chain_key(const vscr_ratchet_t *ratchet, vsc_data_t private_key, vsc_data_t public_key,
        byte new_root_key[vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH], vscr_ratchet_chain_key_t *chain_key) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(chain_key);

    vscr_error_t status = vscr_SUCCESS;

    byte secret[ED25519_DH_LEN];
    int curve_status = curve25519_key_exchange(secret, public_key.bytes, private_key.bytes);
    if (curve_status != 0) {
        status = vscr_error_CURVE25519;
        goto c_err;
    }

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[2 * vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH];
    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_derive(hkdf, vsc_data(secret, sizeof(secret)), vsc_data(ratchet->root_key, sizeof(ratchet->root_key)),
            vsc_data(ratchet_kdf_ratchet_info, sizeof(ratchet_kdf_ratchet_info) - 1), &buffer, sizeof(derived_secret));

    memcpy(new_root_key, derived_secret, vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH);

    memcpy(chain_key->key, derived_secret + vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH,
            vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH);
    chain_key->index = 0;

    vscf_hkdf_destroy(&hkdf);
    vsc_buffer_delete(&buffer);
    vscr_zeroize(derived_secret, sizeof(derived_secret));

c_err:
    vscr_zeroize(secret, sizeof(secret));

    return status;
}

static void
vscr_ratchet_advance_chain_key(vscr_ratchet_chain_key_t *chain_key) {

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

static vscr_ratchet_message_key_t *
vscr_ratchet_create_message_key(const vscr_ratchet_chain_key_t *chain_key) {

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

static vscr_error_t
vscr_ratchet_decrypt_for_existing_chain(vscr_ratchet_t *ratchet, const vscr_ratchet_chain_key_t *chain_key,
        const RegularMessage *message, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(chain_key);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(buffer);

    // This message should be already decrypted
    if (message->counter < chain_key->index) {
        return vscr_error_MESSAGE_ALREADY_DECRYPTED;
    }

    // Too many lost messages
    if (message->counter - chain_key->index > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
        return vscr_error_TOO_MANY_LOST_MESSAGES;
    }

    vscr_ratchet_chain_key_t *new_chain_key = vscr_ratchet_chain_key_new();
    vscr_ratchet_chain_key_clone(chain_key, new_chain_key);

    while (new_chain_key->index < message->counter) {
        vscr_ratchet_advance_chain_key(new_chain_key);
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_create_message_key(new_chain_key);

    vscr_error_t result = vscr_ratchet_cipher_decrypt(ratchet->cipher,
            vsc_data(message_key->key, sizeof(message_key->key)), vsc_buffer_data(message->cipher_text.arg), buffer);

    vscr_ratchet_chain_key_destroy(&new_chain_key);
    vscr_ratchet_message_key_destroy(&message_key);

    return result;
}

static vscr_error_t
vscr_ratchet_decrypt_for_new_chain(vscr_ratchet_t *ratchet, const RegularMessage *message, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(buffer);

    if (!ratchet->sender_chain) {
        return vscr_error_SENDER_CHAIN_MISSING;
    }

    if (message->counter > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
        return vscr_error_TOO_MANY_LOST_MESSAGES;
    }

    byte new_root_key[vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH];

    vscr_ratchet_receiver_chain_t *new_chain = vscr_ratchet_receiver_chain_new();
    vscr_error_t result = vscr_ratchet_create_chain_key(ratchet,
            vsc_data(ratchet->sender_chain->private_key, sizeof(ratchet->sender_chain->private_key)),
            vsc_data(message->public_key, sizeof(message->public_key)), new_root_key, &new_chain->chain_key);

    if (result != vscr_SUCCESS) {
        goto err;
    }

    result = vscr_ratchet_decrypt_for_existing_chain(ratchet, &new_chain->chain_key, message, buffer);

err:
    vscr_ratchet_receiver_chain_destroy(&new_chain);
    vscr_zeroize(new_root_key, sizeof(new_root_key));

    return result;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_respond(vscr_ratchet_t *ratchet, vsc_data_t shared_secret, const RegularMessage *message) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);

    VSCR_ASSERT(!ratchet->receiver_chains);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[2 * vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_derive(hkdf, shared_secret, vsc_data_empty(),
            vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info) - 1), &buffer, sizeof(derived_secret));
    vscf_hkdf_destroy(&hkdf);

    memcpy(ratchet->root_key, derived_secret, vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH);

    vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_receiver_chain_new();
    receiver_chain->chain_key.index = 0;
    memcpy(receiver_chain->chain_key.key, derived_secret + vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH,
            vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH);

    memcpy(receiver_chain->public_key, message->public_key, sizeof(message->public_key));

    vscr_ratchet_add_receiver_chain(ratchet, receiver_chain);

    vsc_buffer_t *msg_buffer =
            vsc_buffer_new_with_capacity(vscr_ratchet_decrypt_len(ratchet, vsc_buffer_len(message->cipher_text.arg)));
    vsc_buffer_make_secure(msg_buffer);
    vscr_error_t status =
            vscr_ratchet_decrypt_for_existing_chain(ratchet, &receiver_chain->chain_key, message, msg_buffer);
    vsc_buffer_destroy(&msg_buffer);

    vscr_ratchet_receiver_chain_destroy(&receiver_chain);
    vscr_zeroize(derived_secret, sizeof(derived_secret));
    vsc_buffer_delete(&buffer);

    return status;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_initiate(vscr_ratchet_t *ratchet, vsc_data_t shared_secret, vsc_data_t ratchet_private_key) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT(ratchet_private_key.len == vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);
    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);
    VSCR_ASSERT(!ratchet->sender_chain);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[2 * vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_derive(hkdf, shared_secret, vsc_data_empty(),
            vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info) - 1), &buffer, sizeof(derived_secret));
    vscf_hkdf_destroy(&hkdf);

    memcpy(ratchet->root_key, derived_secret, vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH);

    vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();
    ratchet->sender_chain = sender_chain;
    memcpy(sender_chain->private_key, ratchet_private_key.bytes, ratchet_private_key.len);
    sender_chain->chain_key.index = 0;
    memcpy(sender_chain->chain_key.key, derived_secret + vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH,
            vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LENGTH);

    vscr_error_t status = vscr_SUCCESS;
    int curve_status = curve25519_get_pubkey(sender_chain->public_key, ratchet_private_key.bytes);
    if (curve_status != 0) {
        vscr_ratchet_sender_chain_destroy(&ratchet->sender_chain);
        status = vscr_error_CURVE25519;
    }

    vscr_zeroize(derived_secret, sizeof(derived_secret));
    vsc_buffer_delete(&buffer);

    return status;
}

VSCR_PUBLIC size_t
vscr_ratchet_encrypt_len(vscr_ratchet_t *ratchet, size_t plain_text_len) {

    VSCR_ASSERT_PTR(ratchet);

    return vscr_ratchet_cipher_encrypt_len(ratchet->cipher, plain_text_len);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_encrypt(vscr_ratchet_t *ratchet, vsc_data_t plain_text, RegularMessage *regular_message) {

    VSCR_ASSERT_PTR(ratchet);

    vscr_error_t result = vscr_SUCCESS;

    if (!ratchet->sender_chain) {
        vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();

        vsc_buffer_t ratchet_private_key;
        vsc_buffer_init(&ratchet_private_key);
        vsc_buffer_use(&ratchet_private_key, sender_chain->private_key, sizeof(sender_chain->private_key));

        vscf_error_t f_status =
                vscf_random(ratchet->rng, vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH, &ratchet_private_key);
        vsc_buffer_delete(&ratchet_private_key);

        if (f_status != vscf_SUCCESS) {
            vscr_ratchet_sender_chain_destroy(&sender_chain);
            return vscr_error_RNG_FAILED;
        }

        ratchet->sender_chain = sender_chain;

        int curve_status = curve25519_get_pubkey(sender_chain->public_key, sender_chain->private_key);

        if (curve_status != 0) {
            return vscr_error_CURVE25519;
        }

        result = vscr_ratchet_create_chain_key(ratchet,
                vsc_data(sender_chain->private_key, sizeof(sender_chain->private_key)),
                vsc_data(ratchet->receiver_chains->value->public_key,
                        sizeof(ratchet->receiver_chains->value->public_key)),
                ratchet->root_key, &sender_chain->chain_key);

        if (result != vscr_SUCCESS) {
            return result;
        }
    }

    if (ratchet->sender_chain->chain_key.index == UINT32_MAX) {
        result = vscr_error_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN;
        goto err1;
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_create_message_key(&ratchet->sender_chain->chain_key);

    vscr_ratchet_advance_chain_key(&ratchet->sender_chain->chain_key);

    result = vscr_ratchet_cipher_encrypt(ratchet->cipher, vsc_data(message_key->key, sizeof(message_key->key)),
            plain_text, regular_message->cipher_text.arg);

    if (result != vscr_SUCCESS) {
        goto err2;
    }

    regular_message->version = vscr_ratchet_common_hidden_RATCHET_REGULAR_MESSAGE_VERSION;
    regular_message->counter = message_key->index;
    regular_message->prev_chain_count = ratchet->prev_sender_chain_count;

    memcpy(regular_message->public_key, ratchet->sender_chain->public_key, sizeof(ratchet->sender_chain->public_key));

err2:
    vscr_ratchet_message_key_destroy(&message_key);

err1:
    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_decrypt_len(vscr_ratchet_t *ratchet, size_t cipher_text_len) {

    VSCR_ASSERT_PTR(ratchet);

    return vscr_ratchet_cipher_decrypt_len(ratchet->cipher, cipher_text_len);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_decrypt(vscr_ratchet_t *ratchet, const RegularMessage *regular_message, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(plain_text);

    if (regular_message->version != vscr_ratchet_common_hidden_RATCHET_REGULAR_MESSAGE_VERSION) {
        return vscr_error_MESSAGE_VERSION_DOESN_T_MATCH;
    }

    vscr_error_t result;

    vscr_ratchet_receiver_chain_list_node_t *receiver_chain_node =
            vscr_ratchet_find_receiver_chain(ratchet, regular_message);
    vscr_ratchet_receiver_chain_t *receiver_chain = receiver_chain_node ? receiver_chain_node->value : NULL;

    if (!receiver_chain || receiver_chain->chain_key.index > regular_message->counter) {
        vscr_ratchet_skipped_message_key_t *skipped_message_key =
                vscr_ratchet_find_skipped_message_key(ratchet, regular_message);

        if (!skipped_message_key) {
            if (receiver_chain) {
                return vscr_error_SKIPPED_MESSAGE_MISSING;
            }
        } else {
            result = vscr_ratchet_cipher_decrypt(ratchet->cipher,
                    vsc_data(skipped_message_key->message_key->key, sizeof(skipped_message_key->message_key->key)),
                    vsc_buffer_data(regular_message->cipher_text.arg), plain_text);

            if (result == vscr_SUCCESS) {
                vscr_ratchet_delete_skipped_message_key(ratchet, skipped_message_key);
            }

            return result;
        }
    }

    if (!receiver_chain) {
        result = vscr_ratchet_decrypt_for_new_chain(ratchet, regular_message, plain_text);
    } else {
        result = vscr_ratchet_decrypt_for_existing_chain(
                ratchet, &receiver_chain->chain_key, regular_message, plain_text);
    }

    if (result != vscr_SUCCESS) {
        return result;
    }

    if (!receiver_chain) {
        vscr_ratchet_receiver_chain_t *new_receiver_chain = vscr_ratchet_receiver_chain_new();

        memcpy(new_receiver_chain->public_key, regular_message->public_key, sizeof(regular_message->public_key));

        // TODO: Optimize
        result = vscr_ratchet_create_chain_key(ratchet,
                vsc_data(ratchet->sender_chain->private_key, sizeof(ratchet->sender_chain->private_key)),
                vsc_data(new_receiver_chain->public_key, sizeof(new_receiver_chain->public_key)), ratchet->root_key,
                &new_receiver_chain->chain_key);

        if (result != vscr_SUCCESS) {
            vscr_ratchet_receiver_chain_destroy(&new_receiver_chain);
            return result;
        }

        receiver_chain_node = vscr_ratchet_add_receiver_chain(ratchet, new_receiver_chain);

        ratchet->prev_sender_chain_count = ratchet->sender_chain->chain_key.index;
        vscr_ratchet_sender_chain_destroy(&ratchet->sender_chain);
        receiver_chain = new_receiver_chain;
        vscr_ratchet_receiver_chain_destroy(&new_receiver_chain);
    }

    while (receiver_chain->chain_key.index < regular_message->counter) {
        vscr_ratchet_skipped_message_key_t *skipped_message_key = vscr_ratchet_skipped_message_key_new();
        skipped_message_key->message_key = vscr_ratchet_create_message_key(&receiver_chain->chain_key);
        memcpy(skipped_message_key->public_key, receiver_chain->public_key, sizeof(receiver_chain->public_key));
        vscr_ratchet_advance_chain_key(&receiver_chain->chain_key);
        vscr_ratchet_add_skipped_message_key(ratchet, skipped_message_key);
        vscr_ratchet_skipped_message_key_destroy(&skipped_message_key);
    }

    if (receiver_chain->chain_key.index == UINT32_MAX) {
        result = vscr_error_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        goto err;
    }

    vscr_ratchet_advance_chain_key(&receiver_chain->chain_key);

    if (receiver_chain_node && receiver_chain_node->next) {
        if (regular_message->prev_chain_count != 0 &&
                receiver_chain_node->next->value->chain_key.index == regular_message->prev_chain_count) {
            vscr_ratchet_delete_next_receiver_chain(receiver_chain_node);
        }
    }

err:
    return result;
}

static vscr_ratchet_receiver_chain_list_node_t *
vscr_ratchet_find_receiver_chain(vscr_ratchet_t *ratchet, const RegularMessage *message) {

    VSCR_ASSERT_PTR(ratchet);

    vscr_ratchet_receiver_chain_list_node_t *chain_list_node = ratchet->receiver_chains;

    while (chain_list_node) {
        if (!memcmp(message->public_key, chain_list_node->value->public_key,
                    vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH)) {
            return chain_list_node;
        }
        chain_list_node = chain_list_node->next;
    }

    return NULL;
}

static vscr_ratchet_receiver_chain_list_node_t *
vscr_ratchet_add_receiver_chain(vscr_ratchet_t *ratchet, vscr_ratchet_receiver_chain_t *receiver_chain) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(receiver_chain);

    vscr_ratchet_receiver_chain_list_node_t *receiver_chain_list_node = vscr_ratchet_receiver_chain_list_node_new();
    receiver_chain_list_node->value = vscr_ratchet_receiver_chain_shallow_copy(receiver_chain);
    receiver_chain_list_node->next = ratchet->receiver_chains;
    ratchet->receiver_chains = receiver_chain_list_node;

    if (!ratchet->receiver_chains->next) {
        return receiver_chain_list_node;
    }

    size_t chains_count = 2;
    while (receiver_chain_list_node->next->next) {
        chains_count += 1;
        receiver_chain_list_node = receiver_chain_list_node->next;
    }

    VSCR_ASSERT(chains_count <= vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS);

    if (chains_count == vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS) {
        vscr_ratchet_receiver_chain_list_node_destroy(&receiver_chain_list_node->next);
    }

    return receiver_chain_list_node;
}

static void
vscr_ratchet_delete_next_receiver_chain(vscr_ratchet_receiver_chain_list_node_t *node) {

    VSCR_ASSERT(node);
    VSCR_ASSERT(node->next);

    vscr_ratchet_receiver_chain_list_node_t *to_delete = node->next;
    node->next = node->next->next;

    to_delete->next = NULL;
    vscr_ratchet_receiver_chain_list_node_destroy(&to_delete);
}

static vscr_ratchet_skipped_message_key_t *
vscr_ratchet_find_skipped_message_key(vscr_ratchet_t *ratchet, const RegularMessage *message) {

    VSCR_ASSERT_PTR(ratchet);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node = ratchet->skipped_message_keys;

    while (skipped_message_key_list_node) {
        if (message->counter == skipped_message_key_list_node->value->message_key->index &&
                !memcmp(message->public_key, skipped_message_key_list_node->value->public_key,
                        vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH)) {
            return skipped_message_key_list_node->value;
        }
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    return NULL;
}

static void
vscr_ratchet_delete_skipped_message_key(
        vscr_ratchet_t *ratchet, vscr_ratchet_skipped_message_key_t *skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(skipped_message_key);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node_prev = NULL;
    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node = ratchet->skipped_message_keys;

    while (skipped_message_key_list_node) {
        if (skipped_message_key_list_node->value == skipped_message_key) {
            if (skipped_message_key_list_node_prev) {
                skipped_message_key_list_node_prev->next = skipped_message_key_list_node->next;
            } else {
                ratchet->skipped_message_keys = skipped_message_key_list_node->next;
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
vscr_ratchet_add_skipped_message_key(vscr_ratchet_t *ratchet, vscr_ratchet_skipped_message_key_t *skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(skipped_message_key);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node =
            vscr_ratchet_skipped_message_key_list_node_new();
    skipped_message_key_list_node->value = vscr_ratchet_skipped_message_key_shallow_copy(skipped_message_key);
    skipped_message_key_list_node->next = ratchet->skipped_message_keys;
    ratchet->skipped_message_keys = skipped_message_key_list_node;

    if (!ratchet->skipped_message_keys->next) {

        return;
    }

    size_t msgs_count = 2;
    while (skipped_message_key_list_node->next->next) {
        msgs_count += 1;
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    VSCR_ASSERT(msgs_count <= vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES);

    if (msgs_count == vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES) {
        vscr_ratchet_skipped_message_key_list_node_destroy(&skipped_message_key_list_node->next);
    }
}

VSCR_PUBLIC void
vscr_ratchet_serialize(vscr_ratchet_t *ratchet, Ratchet *ratchet_pb) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_pb);

    if (ratchet->sender_chain) {
        ratchet_pb->has_sender_chain = true;
        vscr_ratchet_sender_chain_serialize(ratchet->sender_chain, &ratchet_pb->sender_chain);
    } else {
        ratchet_pb->has_sender_chain = false;
    }

    ratchet_pb->prev_sender_chain_count = ratchet->prev_sender_chain_count;
    memcpy(ratchet_pb->root_key, ratchet->root_key, sizeof(ratchet->root_key));

    vscr_ratchet_receiver_chain_list_node_t *receiver_chain = ratchet->receiver_chains;

    pb_size_t chains_count = 0;
    while (receiver_chain) {
        vscr_ratchet_receiver_chain_serialize(receiver_chain->value, &ratchet_pb->receiver_chains[chains_count]);

        chains_count++;
        ratchet_pb->receiver_chains_count = chains_count;
        receiver_chain = receiver_chain->next;
    }

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key = ratchet->skipped_message_keys;

    pb_size_t skipped_count = 0;
    while (skipped_message_key) {
        vscr_ratchet_skipped_message_key_serialize(
                skipped_message_key->value, &ratchet_pb->skipped_message_keys[skipped_count]);

        skipped_count++;
        ratchet_pb->skipped_message_keys_count = skipped_count;
        skipped_message_key = skipped_message_key->next;
    }
}

VSCR_PUBLIC void
vscr_ratchet_deserialize(Ratchet *ratchet_pb, vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_pb);

    if (ratchet_pb->has_sender_chain) {
        ratchet->sender_chain = vscr_ratchet_sender_chain_new();
        vscr_ratchet_sender_chain_deserialize(&ratchet_pb->sender_chain, ratchet->sender_chain);
    }

    ratchet->prev_sender_chain_count = ratchet_pb->prev_sender_chain_count;

    memcpy(ratchet->root_key, ratchet_pb->root_key, sizeof(ratchet->root_key));

    for (pb_size_t i = ratchet_pb->receiver_chains_count; i > 0; i--) {
        vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_receiver_chain_new();

        vscr_ratchet_receiver_chain_deserialize(&ratchet_pb->receiver_chains[i - 1], receiver_chain);

        vscr_ratchet_add_receiver_chain(ratchet, receiver_chain);

        vscr_ratchet_receiver_chain_destroy(&receiver_chain);
    }

    for (pb_size_t i = ratchet_pb->skipped_message_keys_count; i > 0; i--) {
        vscr_ratchet_skipped_message_key_t *skipped_message_key = vscr_ratchet_skipped_message_key_new();

        vscr_ratchet_skipped_message_key_deserialize(&ratchet_pb->skipped_message_keys[i - 1], skipped_message_key);

        vscr_ratchet_add_skipped_message_key(ratchet, skipped_message_key);

        vscr_ratchet_skipped_message_key_destroy(&skipped_message_key);
    }
}
