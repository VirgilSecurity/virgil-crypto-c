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
//  This class provides hybrid encryption algorithm that combines symmetric
//  cipher for data encryption and asymmetric cipher and password based
//  cipher for symmetric key encryption.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_recipient_cipher.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_cipher.h"
#include "vscf_recipient_cipher_defs.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_encrypt.h"
#include "vscf_decrypt.h"
#include "vscf_key_cipher.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_key_recipient_list.h"
#include "vscf_aes256_gcm.h"
#include "vscf_ctr_drbg.h"
#include "vscf_alg_factory.h"
#include "vscf_key_alg_factory.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_recipient_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_recipient_cipher_init_ctx(vscf_recipient_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_recipient_cipher_cleanup_ctx(vscf_recipient_cipher_t *self);

//
//  Configure symmetric cipher with decryption key.
//  Nonce is restored from the message info.
//  Note, this method change decryption state.
//
static vscf_status_t
vscf_recipient_cipher_configure_decryption_cipher(vscf_recipient_cipher_t *self,
        vsc_data_t decryption_key) VSCF_NODISCARD;

//
//  Decrypt data encryption key with a password.
//
static vscf_status_t
vscf_recipient_cipher_decrypt_data_encryption_key_with_password(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

//
//  Decrypt data encryption key with a private key.
//
static vscf_status_t
vscf_recipient_cipher_decrypt_data_encryption_key_with_private_key(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

//
//  Decrypt data encryption key and configure underlying cipher.
//
static vscf_status_t
vscf_recipient_cipher_decrypt_data_encryption_key(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

//
//  Read given message info from the given data or extracted data.
//
static vscf_status_t
vscf_recipient_cipher_unpack_message_info(vscf_recipient_cipher_t *self, vsc_data_t message_info) VSCF_NODISCARD;

static vscf_status_t
vscf_recipient_cipher_extract_message_info(vscf_recipient_cipher_t *self, vsc_data_t data) VSCF_NODISCARD;

//
//  Return size of 'vscf_recipient_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_ctx_size(void) {

    return sizeof(vscf_recipient_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_recipient_cipher_init(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_recipient_cipher_t));

    self->refcnt = 1;

    vscf_recipient_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_recipient_cipher_cleanup(vscf_recipient_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_recipient_cipher_cleanup_ctx(self);

    vscf_recipient_cipher_release_random(self);
    vscf_recipient_cipher_release_encryption_cipher(self);

    vscf_zeroize(self, sizeof(vscf_recipient_cipher_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_recipient_cipher_t *
vscf_recipient_cipher_new(void) {

    vscf_recipient_cipher_t *self = (vscf_recipient_cipher_t *) vscf_alloc(sizeof (vscf_recipient_cipher_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_recipient_cipher_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_recipient_cipher_delete(vscf_recipient_cipher_t *self) {

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

    vscf_recipient_cipher_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_recipient_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_destroy(vscf_recipient_cipher_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_recipient_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vscf_recipient_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_recipient_cipher_t *
vscf_recipient_cipher_shallow_copy(vscf_recipient_cipher_t *self) {

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
vscf_recipient_cipher_use_random(vscf_recipient_cipher_t *self, vscf_impl_t *random) {

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
vscf_recipient_cipher_take_random(vscf_recipient_cipher_t *self, vscf_impl_t *random) {

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
vscf_recipient_cipher_release_random(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_encryption_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encryption_cipher);
    VSCF_ASSERT(self->encryption_cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(encryption_cipher));

    self->encryption_cipher = vscf_impl_shallow_copy(encryption_cipher);
}

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_encryption_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encryption_cipher);
    VSCF_ASSERT(self->encryption_cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(encryption_cipher));

    self->encryption_cipher = encryption_cipher;
}

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_encryption_cipher(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->encryption_cipher);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_recipient_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_recipient_cipher_init_ctx(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    self->message_info = vscf_message_info_new();
    self->message_info_der_serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(self->message_info_der_serializer);

    //  Another properties are allocated by request.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_recipient_cipher_cleanup_ctx(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->decryption_password);
    vsc_buffer_destroy(&self->decryption_recipient_id);
    vscf_impl_destroy(&self->decryption_cipher);
    vscf_impl_destroy(&self->decryption_recipient_key);
    vscf_key_recipient_list_destroy(&self->key_recipients);
    vscf_message_info_der_serializer_destroy(&self->message_info_der_serializer);
    vscf_message_info_destroy(&self->message_info);
}

//
//  Add recipient defined with id and public key.
//
VSCF_PUBLIC void
vscf_recipient_cipher_add_key_recipient(
        vscf_recipient_cipher_t *self, vsc_data_t recipient_id, vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    if (NULL == self->key_recipients) {
        self->key_recipients = vscf_key_recipient_list_new();
    }

    vscf_key_recipient_list_add(self->key_recipients, recipient_id, public_key);
}

//
//  Remove all recipients.
//
VSCF_PUBLIC void
vscf_recipient_cipher_clear_recipients(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_key_recipient_list_destroy(&self->key_recipients);
}

//
//  Provide access to the custom params object.
//  The returned object can be used to add custom params or read it.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_recipient_cipher_custom_params(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);

    return vscf_message_info_custom_params(self->message_info);
}

//
//  Return buffer length required to hold message info returned by the
//  "start encryption" method.
//  Precondition: all recipients and custom parameters should be set.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_message_info_len(const vscf_recipient_cipher_t *self) {

    VSCF_ASSERT(self);

    return vscf_message_info_der_serializer_serialized_len(self->message_info_der_serializer, self->message_info);
}

//
//  Start encryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_encryption(vscf_recipient_cipher_t *self) {

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

    if (NULL == self->encryption_cipher) {
        self->encryption_cipher = vscf_aes256_gcm_impl(vscf_aes256_gcm_new());
    }

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate cipher key and nonce.
    //
    vsc_buffer_t *cipher_key = NULL;
    vsc_buffer_t *cipher_nonce = NULL;

    const size_t cipher_key_len =
            vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->encryption_cipher)));
    const size_t cipher_nonce_len =
            vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->encryption_cipher)));

    cipher_key = vsc_buffer_new_with_capacity(cipher_key_len);
    vsc_buffer_make_secure(cipher_key);

    error.status = vscf_random(self->random, cipher_key_len, cipher_key);
    if (vscf_error_has_error(&error)) {
        goto failed_generate_cipher_key;
    }

    cipher_nonce = vsc_buffer_new_with_capacity(cipher_nonce_len);

    error.status = vscf_random(self->random, cipher_nonce_len, cipher_nonce);
    if (vscf_error_has_error(&error)) {
        goto failed_generate_cipher_nonce;
    }

    //
    //  Encrypt cipher key for each recipient.
    //
    vscf_message_info_clear_recipients(self->message_info);

    for (const vscf_key_recipient_list_t *curr = self->key_recipients; curr != NULL;
            curr = vscf_key_recipient_list_next(curr)) {

        vsc_data_t recipient_id = vscf_key_recipient_list_recipient_id(curr);
        vscf_impl_t *recipient_public_key = vscf_key_recipient_list_recipient_public_key(curr);

        vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(recipient_public_key, self->random, &error);
        if (vscf_error_has_error(&error)) {
            goto failed_build_message_info;
        }
        VSCF_ASSERT(vscf_key_cipher_is_implemented(key_alg));

        const size_t encrypted_key_len = vscf_key_cipher_encrypted_len(key_alg, recipient_public_key, cipher_key_len);
        vsc_buffer_t *encrypted_key = vsc_buffer_new_with_capacity(encrypted_key_len);
        error.status =
                vscf_key_cipher_encrypt(key_alg, recipient_public_key, vsc_buffer_data(cipher_key), encrypted_key);
        vscf_impl_destroy(&key_alg);

        if (vscf_error_has_error(&error)) {
            vsc_buffer_destroy(&encrypted_key);
            goto failed_build_message_info;
        }

        vscf_key_recipient_info_t *recipient_info = vscf_key_recipient_info_new_with_buffer(
                recipient_id, vscf_key_alg_info(recipient_public_key), &encrypted_key);

        vscf_message_info_add_key_recipient(self->message_info, &recipient_info);
    }

    //
    //  TODO: Add password recipients.
    //

    //
    //  Configure cipher key and nonce.
    //
    vscf_cipher_set_key(self->encryption_cipher, vsc_buffer_data(cipher_key));
    vscf_cipher_set_nonce(self->encryption_cipher, vsc_buffer_data(cipher_nonce));
    vscf_cipher_start_encryption(self->encryption_cipher);

    vsc_buffer_destroy(&cipher_key);
    vsc_buffer_destroy(&cipher_nonce);

    //
    //  Append cipher info to the message info.
    //
    vscf_impl_t *data_encryption_alg_info = vscf_alg_produce_alg_info(self->encryption_cipher);
    vscf_message_info_set_data_encryption_alg_info(self->message_info, &data_encryption_alg_info);

    return vscf_status_SUCCESS;

failed_build_message_info:
    vscf_message_info_clear_recipients(self->message_info);

failed_generate_cipher_nonce:
    vsc_buffer_destroy(&cipher_nonce);

failed_generate_cipher_key:
    vsc_buffer_destroy(&cipher_key);

    return vscf_error_status(&error);
}

//
//  Return serialized message info to the buffer.
//
//  Precondition: this method can be called after "start encryption".
//  Precondition: this method can be called before "finish encryption".
//
//  Note, store message info to use it for decryption process,
//  or place it at the encrypted data beginning (embedding).
//
//  Return message info - recipients public information,
//  algorithm information, etc.
//
VSCF_PUBLIC void
vscf_recipient_cipher_pack_message_info(vscf_recipient_cipher_t *self, vsc_buffer_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);
    VSCF_ASSERT(vsc_buffer_is_valid(message_info));
    VSCF_ASSERT(vsc_buffer_unused_len(message_info) >= vscf_recipient_cipher_message_info_len(self));

    vscf_message_info_der_serializer_serialize(self->message_info_der_serializer, self->message_info, message_info);
}

//
//  Return buffer length required to hold output of the method
//  "process encryption" and method "finish" during encryption.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_encryption_out_len(vscf_recipient_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->encryption_cipher);
    VSCF_UNUSED(data_len);

    return vscf_cipher_encrypted_out_len(self->encryption_cipher, data_len);
}

//
//  Process encryption of a new portion of data.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_process_encryption(vscf_recipient_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->encryption_cipher);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_encryption_out_len(self, data.len));

    vscf_cipher_update(self->encryption_cipher, data, out);

    return vscf_status_SUCCESS;
}

//
//  Accomplish encryption.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_finish_encryption(vscf_recipient_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_encryption_out_len(self, 0));

    vscf_status_t status = vscf_cipher_finish(self->encryption_cipher, out);

    return status;
}

//
//  Initiate decryption process with a recipient private key.
//  Message info can be empty if it was embedded to encrypted data.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_decryption_with_key(
        vscf_recipient_cipher_t *self, vsc_data_t recipient_id, vscf_impl_t *private_key, vsc_data_t message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }
        self->random = vscf_ctr_drbg_impl(random);
    }

    vsc_buffer_destroy(&self->decryption_recipient_id);
    vscf_impl_destroy(&self->decryption_recipient_key);
    vsc_buffer_destroy(&self->message_info_buffer);

    self->decryption_recipient_id = vsc_buffer_new_with_data(recipient_id);
    self->decryption_recipient_key = vscf_impl_shallow_copy(private_key);

    vscf_status_t status = vscf_status_SUCCESS;

    if (!vsc_data_is_empty(message_info)) {
        status = vscf_recipient_cipher_unpack_message_info(self, message_info);
        if (status == vscf_status_SUCCESS) {
            status = vscf_recipient_cipher_decrypt_data_encryption_key_with_private_key(self);
        } else {
            self->decryption_state = vscf_recipient_cipher_decryption_state_MESSAGE_INFO_IS_BROKEN;
        }
    } else {
        self->decryption_state = vscf_recipient_cipher_decryption_state_WAITING_MESSAGE_INFO;
        //  TODO: Move to a separate method.
        vsc_buffer_destroy(&self->message_info_buffer);
        self->message_info_buffer = vsc_buffer_new_with_capacity(16);
        self->message_info_expected_len = 0;
    }

    return status;
}

//
//  Return buffer length required to hold output of the method
//  "process decryption" and method "finish" during decryption.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_decryption_out_len(vscf_recipient_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    //
    //  Use constant value, because underlying cipher is not known before,
    //  message info is read.
    //
    //  The size is doubled to be able to decrypt tail
    //  after message info will be extracted.
    //
    size_t len = 2 * (64 + data_len);
    return len;
}

//
//  Process with a new portion of data.
//  Return error if data can not be encrypted or decrypted.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_process_decryption(vscf_recipient_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_decryption_out_len(self, data.len));
    VSCF_ASSERT(self->decryption_state != vscf_recipient_cipher_decryption_state_FAILED);

    switch (self->decryption_state) {
    case vscf_recipient_cipher_decryption_state_PROCESSING_DATA:
        VSCF_ASSERT_PTR(self->decryption_cipher);
        vscf_cipher_update(self->decryption_cipher, data, out);
        return vscf_status_SUCCESS;

    case vscf_recipient_cipher_decryption_state_WAITING_MESSAGE_INFO: {
        vscf_status_t status = vscf_recipient_cipher_extract_message_info(self, data);
        if (status == vscf_status_SUCCESS && (self->message_info_buffer != NULL) &&
                (self->decryption_state == vscf_recipient_cipher_decryption_state_PROCESSING_DATA)) {

            VSCF_ASSERT_PTR(self->decryption_cipher);
            VSCF_ASSERT(vsc_buffer_len(self->message_info_buffer) >= self->message_info_expected_len);
            size_t tail_len = vsc_buffer_len(self->message_info_buffer) - self->message_info_expected_len;
            vsc_data_t tail = vsc_data_slice_end(vsc_buffer_data(self->message_info_buffer), 0, tail_len);
            vscf_cipher_update(self->decryption_cipher, tail, out);
            vsc_buffer_destroy(&self->message_info_buffer);
            self->message_info_expected_len = 0;
        }
        return status;
    }
    default:
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }
}

//
//  Accomplish decryption.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_finish_decryption(vscf_recipient_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_decryption_out_len(self, 0));

    if (self->decryption_state != vscf_recipient_cipher_decryption_state_PROCESSING_DATA) {
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    VSCF_ASSERT_PTR(self->decryption_cipher);
    vscf_status_t status = vscf_cipher_finish(self->decryption_cipher, out);

    vscf_impl_destroy(&self->decryption_cipher);

    return status;
}

//
//  Configure symmetric cipher with decryption key.
//  Nonce is restored from the message info.
//  Note, this method change decryption state.
//
static vscf_status_t
vscf_recipient_cipher_configure_decryption_cipher(vscf_recipient_cipher_t *self, vsc_data_t decryption_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);

    vscf_impl_destroy(&self->decryption_cipher);

    const vscf_impl_t *cipher_alg_info = vscf_message_info_data_encryption_alg_info(self->message_info);
    self->decryption_cipher = vscf_alg_factory_create_cipher_from_info(cipher_alg_info);

    vscf_cipher_set_key(self->decryption_cipher, decryption_key);
    vscf_cipher_start_decryption(self->decryption_cipher);

    self->decryption_state = vscf_recipient_cipher_decryption_state_PROCESSING_DATA;

    return vscf_status_SUCCESS;
}

//
//  Decrypt data encryption key with a password.
//
static vscf_status_t
vscf_recipient_cipher_decrypt_data_encryption_key_with_password(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(self->decryption_password);

    return vscf_status_SUCCESS;
}

//
//  Decrypt data encryption key with a private key.
//
static vscf_status_t
vscf_recipient_cipher_decrypt_data_encryption_key_with_private_key(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(self->decryption_recipient_id);
    VSCF_ASSERT_PTR(self->decryption_recipient_key);

    vsc_data_t recipient_id = vsc_buffer_data(self->decryption_recipient_id);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Iterate recipients.
    //
    for (const vscf_key_recipient_info_list_t *curr = vscf_message_info_key_recipient_info_list(self->message_info);
            curr != NULL && vscf_key_recipient_info_list_has_item(curr);
            curr = vscf_key_recipient_info_list_next(curr)) {
        //
        //  Find recipient.
        //
        const vscf_key_recipient_info_t *recipient_info = vscf_key_recipient_info_list_item(curr);
        if (vsc_data_equal(vscf_key_recipient_info_recipient_id(recipient_info), recipient_id)) {
            //
            //  Compare algorithms.
            //
            const vscf_impl_t *encryption_algorithm = vscf_key_recipient_info_key_encryption_algorithm(recipient_info);

            vscf_alg_id_t encryption_algorithm_alg_id = vscf_alg_info_alg_id(encryption_algorithm);
            vscf_alg_id_t decryption_algorithm_alg_id = vscf_key_alg_id(self->decryption_recipient_key);

            if (encryption_algorithm_alg_id != decryption_algorithm_alg_id) {
                return vscf_status_ERROR_BAD_MESSAGE_INFO;
            }

            vscf_impl_t *key_alg =
                    vscf_key_alg_factory_create_from_key(self->decryption_recipient_key, self->random, &error);
            if (vscf_error_has_error(&error)) {
                return vscf_error_status(&error);
            }

            //
            //  Decrypt decryption key.
            //
            vsc_data_t encrypted_key = vscf_key_recipient_info_encrypted_key(recipient_info);

            const size_t decryption_key_len =
                    vscf_key_cipher_decrypted_len(key_alg, self->decryption_recipient_key, encrypted_key.len);
            vsc_buffer_t *decryption_key = vsc_buffer_new_with_capacity(decryption_key_len);
            vsc_buffer_make_secure(decryption_key);

            vscf_status_t status =
                    vscf_key_cipher_decrypt(key_alg, self->decryption_recipient_key, encrypted_key, decryption_key);

            vscf_impl_destroy(&key_alg);

            if (status != vscf_status_SUCCESS) {
                vsc_buffer_destroy(&decryption_key);
                return vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG;
            }

            //
            //  Configure cipher.
            //
            status = vscf_recipient_cipher_configure_decryption_cipher(self, vsc_buffer_data(decryption_key));
            vsc_buffer_destroy(&decryption_key);

            return status;
        }
    }

    return vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND;
}

//
//  Decrypt data encryption key and configure underlying cipher.
//
static vscf_status_t
vscf_recipient_cipher_decrypt_data_encryption_key(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);

    if (self->decryption_recipient_id != NULL) {
        return vscf_recipient_cipher_decrypt_data_encryption_key_with_private_key(self);
    } else {
        return vscf_recipient_cipher_decrypt_data_encryption_key_with_password(self);
    }
}

//
//  Read given message info from the given data or extracted data.
//
static vscf_status_t
vscf_recipient_cipher_unpack_message_info(vscf_recipient_cipher_t *self, vsc_data_t message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info_der_serializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_message_info_destroy(&self->message_info);
    self->message_info =
            vscf_message_info_der_serializer_deserialize(self->message_info_der_serializer, message_info, &error);

    return vscf_error_status(&error);
}

static vscf_status_t
vscf_recipient_cipher_extract_message_info(vscf_recipient_cipher_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info_der_serializer);
    VSCF_ASSERT(vsc_data_is_valid(data));

    VSCF_ASSERT(self->decryption_state == vscf_recipient_cipher_decryption_state_WAITING_MESSAGE_INFO);
    VSCF_ASSERT(self->message_info_buffer);

    if (vsc_buffer_unused_len(self->message_info_buffer) < data.len) {
        //  Increase buffer capacity.
        vsc_buffer_t *new_message_info_buffer =
                vsc_buffer_new_with_capacity(vsc_buffer_len(self->message_info_buffer) + data.len);
        vsc_buffer_write_data(new_message_info_buffer, vsc_buffer_data(self->message_info_buffer));
        vsc_buffer_destroy(&self->message_info_buffer);
        self->message_info_buffer = new_message_info_buffer;
    }

    vsc_buffer_write_data(self->message_info_buffer, data);

    if (vsc_buffer_len(self->message_info_buffer) < vscf_message_info_der_serializer_PREFIX_LEN) {
        return vscf_status_SUCCESS;
    }

    if (self->message_info_expected_len == 0) {
        vsc_data_t message_info = vsc_buffer_data(self->message_info_buffer);

        self->message_info_expected_len =
                vscf_message_info_der_serializer_read_prefix(self->message_info_der_serializer, message_info);

        if (self->message_info_expected_len == 0) {
            self->decryption_state = vscf_recipient_cipher_decryption_state_MESSAGE_INFO_IS_ABSENT;
            return vscf_status_ERROR_NO_MESSAGE_INFO;
        }
    }

    if (vsc_buffer_len(self->message_info_buffer) >= self->message_info_expected_len) {
        vsc_data_t message_info =
                vsc_data_slice_beg(vsc_buffer_data(self->message_info_buffer), 0, self->message_info_expected_len);

        vscf_status_t status = vscf_recipient_cipher_unpack_message_info(self, message_info);

        if (status == vscf_status_SUCCESS) {
            return vscf_recipient_cipher_decrypt_data_encryption_key(self);
        } else {
            //  Also ABSENT, because first several bytes of an encrypted data
            //  can be a valid message info prefix.
            self->decryption_state = vscf_recipient_cipher_decryption_state_MESSAGE_INFO_IS_ABSENT;
            return vscf_status_ERROR_NO_MESSAGE_INFO;
        }
    }

    return vscf_status_SUCCESS;
}
