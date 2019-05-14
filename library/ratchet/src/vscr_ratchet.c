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
#include "vscr_ratchet_defs.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_ratchet_receiver_chain.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_sender_chain.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <ed25519/ed25519.h>

// clang-format on
//  @end


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
vscr_ratchet_init_ctx(vscr_ratchet_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cleanup_ctx(vscr_ratchet_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_did_setup_rng(vscr_ratchet_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_did_release_rng(vscr_ratchet_t *self);

static vscr_status_t
vscr_ratchet_decrypt_for_existing_chain(vscr_ratchet_t *self, const vscr_ratchet_chain_key_t *chain_key,
        const RegularMessage *message, const RegularMessageHeader *regular_message_header,
        vsc_buffer_t *buffer) VSCR_NODISCARD;

static vscr_status_t
vscr_ratchet_decrypt_for_new_chain(vscr_ratchet_t *self, const RegularMessage *message,
        const RegularMessageHeader *regular_message_header, vsc_buffer_t *buffer) VSCR_NODISCARD;

static vscr_status_t
vscr_ratchet_generate_sender_chain_keypair(vscr_ratchet_t *self,
        vscr_ratchet_sender_chain_t *sender_chain) VSCR_NODISCARD;

static vscr_status_t
vscr_ratchet_generate_skipped_keys(vscr_ratchet_t *self, vscr_ratchet_receiver_chain_t *receiver_chain,
        size_t counter) VSCR_NODISCARD;

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
vscr_ratchet_init(vscr_ratchet_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_t));

    self->refcnt = 1;

    vscr_ratchet_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_cleanup(vscr_ratchet_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_cleanup_ctx(self);

        vscr_ratchet_release_rng(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_new(void) {

    vscr_ratchet_t *self = (vscr_ratchet_t *) vscr_alloc(sizeof (vscr_ratchet_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_delete(vscr_ratchet_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_destroy(vscr_ratchet_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_t *
vscr_ratchet_shallow_copy(vscr_ratchet_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_use_rng(vscr_ratchet_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);

    vscr_ratchet_did_setup_rng(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_take_rng(vscr_ratchet_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;

    vscr_ratchet_did_setup_rng(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_release_rng(vscr_ratchet_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);

    vscr_ratchet_did_release_rng(self);
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
vscr_ratchet_init_ctx(vscr_ratchet_t *self) {

    VSCR_ASSERT_PTR(self);

    self->skipped_messages = vscr_ratchet_skipped_messages_new();
    self->cipher = vscr_ratchet_cipher_new();
    self->padding = vscr_ratchet_padding_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cleanup_ctx(vscr_ratchet_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_sender_chain_destroy(&self->sender_chain);
    vscr_ratchet_receiver_chain_destroy(&self->receiver_chain);
    vscr_ratchet_skipped_messages_destroy(&self->skipped_messages);
    vscr_ratchet_cipher_destroy(&self->cipher);
    vscr_ratchet_padding_destroy(&self->padding);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_did_setup_rng(vscr_ratchet_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->rng) {
        vscr_ratchet_padding_use_rng(self->padding, self->rng);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_did_release_rng(vscr_ratchet_t *self) {

    VSCR_UNUSED(self);
}

static vscr_status_t
vscr_ratchet_decrypt_for_existing_chain(vscr_ratchet_t *self, const vscr_ratchet_chain_key_t *chain_key,
        const RegularMessage *message, const RegularMessageHeader *regular_message_header, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(chain_key);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(buffer);
    VSCR_ASSERT_PTR(regular_message_header);

    // This message should be already decrypted
    if (regular_message_header->counter < chain_key->index) {
        return vscr_status_ERROR_MESSAGE_ALREADY_DECRYPTED;
    }

    // Too many lost messages
    if (regular_message_header->counter - chain_key->index > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
        return vscr_status_ERROR_TOO_MANY_LOST_MESSAGES;
    }

    vscr_ratchet_chain_key_t *new_chain_key = vscr_ratchet_chain_key_new();
    vscr_ratchet_chain_key_clone(chain_key, new_chain_key);

    while (new_chain_key->index < regular_message_header->counter) {
        if (new_chain_key->index == UINT32_MAX) {
            vscr_ratchet_chain_key_destroy(&new_chain_key);
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }
        vscr_ratchet_keys_advance_chain_key(new_chain_key);
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(new_chain_key);

    vscr_status_t result =
            vscr_ratchet_cipher_decrypt_then_remove_pad(self->cipher, vsc_buffer_data(message->cipher_text.arg),
                    message_key, vsc_data(message->header.bytes, message->header.size), buffer);

    vscr_ratchet_chain_key_destroy(&new_chain_key);
    vscr_ratchet_message_key_destroy(&message_key);

    return result;
}

static vscr_status_t
vscr_ratchet_decrypt_for_new_chain(vscr_ratchet_t *self, const RegularMessage *message,
        const RegularMessageHeader *regular_message_header, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(buffer);
    VSCR_ASSERT_PTR(regular_message_header);

    if (!self->sender_chain) {
        return vscr_status_ERROR_SENDER_CHAIN_MISSING;
    }

    if (regular_message_header->counter > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
        return vscr_status_ERROR_TOO_MANY_LOST_MESSAGES;
    }

    byte new_root_key[vscr_ratchet_common_hidden_SHARED_KEY_LEN];

    vscr_ratchet_receiver_chain_t *new_chain = vscr_ratchet_receiver_chain_new();
    vscr_status_t result = vscr_ratchet_keys_create_chain_key(self->root_key, self->sender_chain->private_key,
            regular_message_header->public_key, new_root_key, &new_chain->chain_key);

    if (result != vscr_status_SUCCESS) {
        goto err;
    }

    result = vscr_ratchet_decrypt_for_existing_chain(
            self, &new_chain->chain_key, message, regular_message_header, buffer);

err:
    vscr_ratchet_receiver_chain_destroy(&new_chain);
    vscr_zeroize(new_root_key, sizeof(new_root_key));

    return result;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_respond(vscr_ratchet_t *self, vsc_data_t shared_secret, const RegularMessage *message,
        const RegularMessageHeader *regular_message_header) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);

    VSCR_ASSERT(!self->receiver_chain);

    vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_receiver_chain_new();
    receiver_chain->chain_key.index = 0;

    vscr_ratchet_keys_derive_initial_keys(shared_secret, self->root_key, receiver_chain->chain_key.key);

    memcpy(receiver_chain->public_key, regular_message_header->public_key, sizeof(regular_message_header->public_key));

    self->receiver_chain = receiver_chain;

    vscr_ratchet_skipped_messages_add_public_key(self->skipped_messages, regular_message_header->public_key);

    // TODO: Optimize. Prevent double decrypt for first message if possible
    // At this moment decrypting message using symmetric authenticated encryption is the only way to check
    // message authenticity. Further in decrypt method first message will be decrypted for the second time.

    vsc_buffer_t *msg_buffer =
            vsc_buffer_new_with_capacity(vscr_ratchet_decrypt_len(self, vsc_buffer_len(message->cipher_text.arg)));
    vsc_buffer_make_secure(msg_buffer);
    vscr_status_t status = vscr_ratchet_decrypt_for_existing_chain(
            self, &receiver_chain->chain_key, message, regular_message_header, msg_buffer);
    vsc_buffer_destroy(&msg_buffer);

    return status;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_initiate(vscr_ratchet_t *self, vsc_data_t shared_secret) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);
    VSCR_ASSERT(!self->sender_chain);

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();

    status = vscr_ratchet_generate_sender_chain_keypair(self, sender_chain);

    if (status != vscr_status_SUCCESS) {
        vscr_ratchet_sender_chain_destroy(&sender_chain);
        return status;
    }

    sender_chain->chain_key.index = 0;

    vscr_ratchet_keys_derive_initial_keys(shared_secret, self->root_key, sender_chain->chain_key.key);

    self->sender_chain = sender_chain;

    return status;
}

VSCR_PUBLIC size_t
vscr_ratchet_encrypt_len(vscr_ratchet_t *self, size_t plain_text_len) {

    VSCR_ASSERT_PTR(self);

    return vscr_ratchet_cipher_encrypt_len(self->cipher, vscr_ratchet_padding_padded_len(plain_text_len));
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_encrypt(vscr_ratchet_t *self, vsc_data_t plain_text, RegularMessage *regular_message,
        RegularMessageHeader *regular_message_header) {

    VSCR_ASSERT_PTR(self);

    vscr_status_t result = vscr_status_SUCCESS;

    if (!self->sender_chain) {
        vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();

        result = vscr_ratchet_generate_sender_chain_keypair(self, sender_chain);

        if (result != vscr_status_SUCCESS) {
            vscr_ratchet_sender_chain_destroy(&sender_chain);
            return result;
        }

        result = vscr_ratchet_keys_create_chain_key(self->root_key, sender_chain->private_key,
                self->receiver_chain->public_key, self->root_key, &sender_chain->chain_key);

        if (result != vscr_status_SUCCESS) {
            return result;
        }
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(&self->sender_chain->chain_key);

    if (self->sender_chain->chain_key.index == UINT32_MAX) {
        result = vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN;
        goto err1;
    }

    vscr_ratchet_keys_advance_chain_key(&self->sender_chain->chain_key);

    regular_message_header->counter = message_key->index;
    regular_message_header->prev_chain_count = self->prev_sender_chain_count;

    memcpy(regular_message_header->public_key, self->sender_chain->public_key, sizeof(self->sender_chain->public_key));

    pb_ostream_t ostream = pb_ostream_from_buffer(regular_message->header.bytes, sizeof(regular_message->header.bytes));

    VSCR_ASSERT(pb_encode(&ostream, RegularMessageHeader_fields, regular_message_header));

    regular_message->header.size = ostream.bytes_written;

    result = vscr_ratchet_cipher_pad_then_encrypt(self->cipher, self->padding, plain_text, message_key,
            vsc_data(regular_message->header.bytes, regular_message->header.size), regular_message->cipher_text.arg);

err1:
    vscr_ratchet_message_key_destroy(&message_key);

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_decrypt_len(vscr_ratchet_t *self, size_t cipher_text_len) {

    VSCR_ASSERT_PTR(self);

    return vscr_ratchet_cipher_decrypt_len(self->cipher, cipher_text_len);
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_decrypt(vscr_ratchet_t *self, const RegularMessage *regular_message,
        const RegularMessageHeader *regular_message_header, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(plain_text);
    VSCR_ASSERT_PTR(regular_message);
    VSCR_ASSERT_PTR(regular_message_header);

    vscr_ratchet_receiver_chain_t *receiver_chain = NULL;

    if (self->receiver_chain && memcmp(regular_message_header->public_key, self->receiver_chain->public_key,
                                        sizeof(regular_message_header->public_key)) == 0) {
        receiver_chain = self->receiver_chain;
    }

    if (!receiver_chain || receiver_chain->chain_key.index > regular_message_header->counter) {
        vscr_ratchet_message_key_t *skipped_message_key = vscr_ratchet_skipped_messages_find_key(
                self->skipped_messages, regular_message_header->counter, regular_message_header->public_key);

        if (!skipped_message_key) {
            if (receiver_chain) {
                return vscr_status_ERROR_SKIPPED_MESSAGE_MISSING;
            }
        } else {
            vscr_status_t result = vscr_ratchet_cipher_decrypt_then_remove_pad(self->cipher,
                    vsc_buffer_data(regular_message->cipher_text.arg), skipped_message_key,
                    vsc_data(regular_message->header.bytes, regular_message->header.size), plain_text);

            if (result != vscr_status_SUCCESS) {
                return result;
            }

            vscr_ratchet_skipped_messages_delete_key(
                    self->skipped_messages, regular_message_header->public_key, skipped_message_key);

            return vscr_status_SUCCESS;
        }
    }

    if (!receiver_chain) {
        vscr_status_t result =
                vscr_ratchet_decrypt_for_new_chain(self, regular_message, regular_message_header, plain_text);

        if (result != vscr_status_SUCCESS) {
            return result;
        }
    } else {
        vscr_status_t result = vscr_ratchet_decrypt_for_existing_chain(
                self, &receiver_chain->chain_key, regular_message, regular_message_header, plain_text);

        if (result != vscr_status_SUCCESS) {
            return result;
        }
    }

    vscr_ratchet_receiver_chain_t *old_chain = NULL;

    if (!receiver_chain) {
        vscr_ratchet_receiver_chain_t *new_receiver_chain = vscr_ratchet_receiver_chain_new();

        memcpy(new_receiver_chain->public_key, regular_message_header->public_key,
                sizeof(regular_message_header->public_key));

        vscr_status_t result = vscr_ratchet_keys_create_chain_key(self->root_key, self->sender_chain->private_key,
                new_receiver_chain->public_key, self->root_key, &new_receiver_chain->chain_key);

        if (result != vscr_status_SUCCESS) {
            vscr_ratchet_receiver_chain_destroy(&new_receiver_chain);
            return result;
        }

        old_chain = self->receiver_chain;
        self->receiver_chain = new_receiver_chain;

        self->prev_sender_chain_count = self->sender_chain->chain_key.index;
        vscr_ratchet_sender_chain_destroy(&self->sender_chain);
        receiver_chain = new_receiver_chain;

        vscr_ratchet_skipped_messages_add_public_key(self->skipped_messages, regular_message_header->public_key);
    }

    vscr_status_t result;

    if (old_chain) {
        result = vscr_ratchet_generate_skipped_keys(self, old_chain, regular_message_header->prev_chain_count);
        vscr_ratchet_receiver_chain_destroy(&old_chain);

        if (result != vscr_status_SUCCESS) {
            return result;
        }
    }

    result = vscr_ratchet_generate_skipped_keys(self, receiver_chain, regular_message_header->counter);

    if (result != vscr_status_SUCCESS) {
        return result;
    }

    if (receiver_chain->chain_key.index == UINT32_MAX) {
        return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
    }

    vscr_ratchet_keys_advance_chain_key(&receiver_chain->chain_key);

    return vscr_status_SUCCESS;
}

static vscr_status_t
vscr_ratchet_generate_sender_chain_keypair(vscr_ratchet_t *self, vscr_ratchet_sender_chain_t *sender_chain) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);
    VSCR_ASSERT_PTR(sender_chain);

    vsc_buffer_t ratchet_private_key;
    vsc_buffer_init(&ratchet_private_key);
    vsc_buffer_use(&ratchet_private_key, sender_chain->private_key, sizeof(sender_chain->private_key));

    vscf_status_t f_status = vscf_random(self->rng, vscr_ratchet_common_hidden_KEY_LEN, &ratchet_private_key);
    vsc_buffer_delete(&ratchet_private_key);

    if (f_status != vscf_status_SUCCESS) {
        return vscr_status_ERROR_RNG_FAILED;
    }

    self->sender_chain = sender_chain;

    int curve_status = curve25519_get_pubkey(sender_chain->public_key, sender_chain->private_key);

    if (curve_status != 0) {
        return vscr_status_ERROR_CURVE25519;
    }

    return vscr_status_SUCCESS;
}

static vscr_status_t
vscr_ratchet_generate_skipped_keys(
        vscr_ratchet_t *self, vscr_ratchet_receiver_chain_t *receiver_chain, size_t counter) {

    while (receiver_chain->chain_key.index < counter) {
        vscr_ratchet_message_key_t *skipped_message_key =
                vscr_ratchet_keys_create_message_key(&receiver_chain->chain_key);
        if (receiver_chain->chain_key.index == UINT32_MAX) {
            vscr_ratchet_message_key_destroy(&skipped_message_key);
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }
        vscr_ratchet_keys_advance_chain_key(&receiver_chain->chain_key);
        vscr_ratchet_skipped_messages_add_key(self->skipped_messages, receiver_chain->public_key, skipped_message_key);
    }

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC void
vscr_ratchet_serialize(const vscr_ratchet_t *self, Ratchet *ratchet_pb) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(ratchet_pb);

    if (self->sender_chain) {
        ratchet_pb->has_sender_chain = true;
        vscr_ratchet_sender_chain_serialize(self->sender_chain, &ratchet_pb->sender_chain);
    } else {
        ratchet_pb->has_sender_chain = false;
    }

    ratchet_pb->prev_sender_chain_count = self->prev_sender_chain_count;

    if (self->receiver_chain) {
        ratchet_pb->has_receiver_chain = true;
        vscr_ratchet_receiver_chain_serialize(self->receiver_chain, &ratchet_pb->receiver_chain);
    } else {
        ratchet_pb->has_receiver_chain = false;
    }

    memcpy(ratchet_pb->root_key, self->root_key, sizeof(self->root_key));

    vscr_ratchet_skipped_messages_serialize(self->skipped_messages, &ratchet_pb->skipped_messages);
}

VSCR_PUBLIC void
vscr_ratchet_deserialize(const Ratchet *ratchet_pb, vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_pb);

    if (ratchet_pb->has_sender_chain) {
        ratchet->sender_chain = vscr_ratchet_sender_chain_new();
        vscr_ratchet_sender_chain_deserialize(&ratchet_pb->sender_chain, ratchet->sender_chain);
    }

    ratchet->prev_sender_chain_count = ratchet_pb->prev_sender_chain_count;

    if (ratchet_pb->has_receiver_chain) {
        ratchet->receiver_chain = vscr_ratchet_receiver_chain_new();
        vscr_ratchet_receiver_chain_deserialize(&ratchet_pb->receiver_chain, ratchet->receiver_chain);
    }

    memcpy(ratchet->root_key, ratchet_pb->root_key, sizeof(ratchet->root_key));

    vscr_ratchet_skipped_messages_deserialize(&ratchet_pb->skipped_messages, ratchet->skipped_messages);
}
