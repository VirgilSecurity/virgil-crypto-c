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
//  Add and/or remove recipients and it's paramteres within message info.
//
//  Usage:
//    1. Unpack binary message info that was obtained from RecipientCipher.
//    2. Add and/or remove key recipients.
//    3. Pack MessagInfo to the binary data.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_info_editor.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_message_info_editor_defs.h"
#include "vscf_encrypt.h"
#include "vscf_decrypt.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_key_cipher.h"
#include "vscf_message_info_serializer.h"
#include "vscf_alg_factory.h"
#include "vscf_key_alg_factory.h"
#include "vscf_key_provider.h"
#include "vscf_ctr_drbg.h"
#include "vscf_message_info_der_serializer.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_info_editor_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_info_editor_init_ctx(vscf_message_info_editor_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_info_editor_cleanup_ctx(vscf_message_info_editor_t *self);

//
//  Return size of 'vscf_message_info_editor_t'.
//
VSCF_PUBLIC size_t
vscf_message_info_editor_ctx_size(void) {

    return sizeof(vscf_message_info_editor_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_info_editor_init(vscf_message_info_editor_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_message_info_editor_t));

    self->refcnt = 1;

    vscf_message_info_editor_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_editor_cleanup(vscf_message_info_editor_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_message_info_editor_cleanup_ctx(self);

    vscf_message_info_editor_release_random(self);

    vscf_zeroize(self, sizeof(vscf_message_info_editor_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_info_editor_t *
vscf_message_info_editor_new(void) {

    vscf_message_info_editor_t *self = (vscf_message_info_editor_t *) vscf_alloc(sizeof (vscf_message_info_editor_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_message_info_editor_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_message_info_editor_delete(vscf_message_info_editor_t *self) {

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

    vscf_message_info_editor_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_info_editor_new ()'.
//
VSCF_PUBLIC void
vscf_message_info_editor_destroy(vscf_message_info_editor_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_message_info_editor_t *self = *self_ref;
    *self_ref = NULL;

    vscf_message_info_editor_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_editor_t *
vscf_message_info_editor_shallow_copy(vscf_message_info_editor_t *self) {

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
vscf_message_info_editor_use_random(vscf_message_info_editor_t *self, vscf_impl_t *random) {

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
vscf_message_info_editor_take_random(vscf_message_info_editor_t *self, vscf_impl_t *random) {

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
vscf_message_info_editor_release_random(vscf_message_info_editor_t *self) {

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
//  Note, this method is called automatically when method vscf_message_info_editor_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_info_editor_init_ctx(vscf_message_info_editor_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_message_info_der_serializer_t *der_serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(der_serializer);
    self->message_info_serializer = vscf_message_info_der_serializer_impl(der_serializer);

    self->encryption_key = vsc_buffer_new();
    vsc_buffer_make_secure(self->encryption_key);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_info_editor_cleanup_ctx(vscf_message_info_editor_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->message_info_serializer);
    vsc_buffer_destroy(&self->encryption_key);
}

//
//  Set depenencies to it's defaults.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_setup_defaults(vscf_message_info_editor_t *self) {

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
//  Unpack serialized message info.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_unpack(vscf_message_info_editor_t *self, vsc_data_t message_info_data,
        vsc_data_t owner_recipient_id, const vscf_impl_t *owner_private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->message_info_serializer);
    VSCF_ASSERT(vsc_data_is_valid(message_info_data));
    VSCF_ASSERT(vsc_data_is_valid(owner_recipient_id));
    VSCF_ASSERT_PTR(owner_private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(owner_private_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Cleanup
    //
    vscf_message_info_destroy(&self->message_info);
    vsc_buffer_release(self->encryption_key);

    self->message_info =
            vscf_message_info_serializer_deserialize(self->message_info_serializer, message_info_data, &error);

    if (vscf_error_has_error(&error)) {
        return vscf_error_status(&error);
    }

    //
    //  Decrypt encryption key.
    //
    for (const vscf_key_recipient_info_list_t *curr = vscf_message_info_key_recipient_info_list(self->message_info);
            (curr != NULL) && vscf_key_recipient_info_list_has_item(curr);
            curr = vscf_key_recipient_info_list_next(curr)) {
        //
        //  Find recipient.
        //
        const vscf_key_recipient_info_t *recipient_info = vscf_key_recipient_info_list_item(curr);
        if (vsc_data_equal(vscf_key_recipient_info_recipient_id(recipient_info), owner_recipient_id)) {
            //
            //  Check algorithm that was used for encryption to be equal algorithm that will be used for
            //  decryption.
            //
            const vscf_impl_t *encryption_algorithm = vscf_key_recipient_info_key_encryption_algorithm(recipient_info);

            vscf_alg_id_t encryption_algorithm_alg_id = vscf_alg_info_alg_id(encryption_algorithm);
            vscf_alg_id_t decryption_algorithm_alg_id = vscf_key_alg_id(owner_private_key);

            if (encryption_algorithm_alg_id != decryption_algorithm_alg_id) {
                return vscf_status_ERROR_BAD_MESSAGE_INFO;
            }

            vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(owner_private_key, self->random, &error);
            if (vscf_error_has_error(&error)) {
                return vscf_error_status(&error);
            }

            //
            //  Decrypt encryption key.
            //
            vsc_data_t encrypted_key = vscf_key_recipient_info_encrypted_key(recipient_info);

            const size_t encryption_key_len =
                    vscf_key_cipher_decrypted_len(key_alg, owner_private_key, encrypted_key.len);
            vsc_buffer_alloc(self->encryption_key, encryption_key_len);

            vscf_status_t status =
                    vscf_key_cipher_decrypt(key_alg, owner_private_key, encrypted_key, self->encryption_key);

            vscf_impl_destroy(&key_alg);

            if (status != vscf_status_SUCCESS) {
                return vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG;
            }

            return vscf_status_SUCCESS;
        }
    }

    return vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND;
}

//
//  Add recipient defined with id and public key.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_add_key_recipient(
        vscf_message_info_editor_t *self, vsc_data_t recipient_id, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(vsc_buffer_is_valid(self->encryption_key));
    VSCF_ASSERT(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(public_key, self->random, &error);
    if (vscf_error_has_error(&error)) {
        return vscf_error_status(&error);
    }
    VSCF_ASSERT(vscf_key_cipher_is_implemented(key_alg));

    const size_t encrypted_key_len =
            vscf_key_cipher_encrypted_len(key_alg, public_key, vsc_buffer_len(self->encryption_key));
    vsc_buffer_t *encrypted_key = vsc_buffer_new_with_capacity(encrypted_key_len);
    error.status = vscf_key_cipher_encrypt(key_alg, public_key, vsc_buffer_data(self->encryption_key), encrypted_key);
    vscf_impl_destroy(&key_alg);

    if (vscf_error_has_error(&error)) {
        vsc_buffer_destroy(&encrypted_key);
        return vscf_error_status(&error);
    }

    vscf_key_recipient_info_t *recipient_info =
            vscf_key_recipient_info_new_with_buffer(recipient_id, vscf_key_alg_info(public_key), &encrypted_key);

    vscf_message_info_add_key_recipient(self->message_info, &recipient_info);

    return vscf_status_SUCCESS;
}

//
//  Remove recipient with a given id.
//  Return false if recipient with given id was not found.
//
VSCF_PUBLIC bool
vscf_message_info_editor_remove_key_recipient(vscf_message_info_editor_t *self, vsc_data_t recipient_id) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT(vsc_data_is_valid(recipient_id));

    for (vscf_key_recipient_info_list_t *curr =
                    vscf_message_info_key_recipient_info_list_modifiable(self->message_info);
            (curr != NULL) && vscf_key_recipient_info_list_has_item(curr);
            curr = vscf_key_recipient_info_list_next_modifiable(curr)) {
        //
        //  Find recipient.
        //
        const vscf_key_recipient_info_t *recipient_info = vscf_key_recipient_info_list_item(curr);
        if (vsc_data_equal(vscf_key_recipient_info_recipient_id(recipient_info), recipient_id)) {
            vscf_key_recipient_info_list_remove_self(curr);
            return true;
        }
    }

    return false;
}

//
//  Remove all existent recipients.
//
VSCF_PUBLIC void
vscf_message_info_editor_remove_all(vscf_message_info_editor_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);

    vscf_key_recipient_info_list_t *key_recipients =
            vscf_message_info_key_recipient_info_list_modifiable(self->message_info);
    vscf_key_recipient_info_list_clear(key_recipients);
}

//
//  Return length of serialized message info.
//  Actual length can be obtained right after applying changes.
//
VSCF_PUBLIC size_t
vscf_message_info_editor_packed_len(const vscf_message_info_editor_t *self) {

    VSCF_ASSERT(self);
    VSCF_ASSERT(self->message_info);
    VSCF_ASSERT(self->message_info_serializer);

    return vscf_message_info_serializer_serialized_len(self->message_info_serializer, self->message_info);
}

//
//  Return serialized message info.
//  Precondition: this method can be called after "apply".
//
VSCF_PUBLIC void
vscf_message_info_editor_pack(vscf_message_info_editor_t *self, vsc_buffer_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(self->message_info_serializer);
    VSCF_ASSERT_PTR(message_info);
    VSCF_ASSERT(vsc_buffer_is_valid(message_info));
    VSCF_ASSERT(vsc_buffer_unused_len(message_info) >= vscf_message_info_editor_packed_len(self));

    vscf_message_info_serializer_serialize(self->message_info_serializer, self->message_info, message_info);
}
