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
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_encrypt.h"
#include "vscf_decrypt.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_key_recipient_list.h"
#include "vscf_aes256_gcm.h"
#include "vscf_ctr_drbg.h"

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

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_recipient_cipher_cleanup_ctx(self);

        vscf_recipient_cipher_release_random(self);
        vscf_recipient_cipher_release_cipher(self);

        vscf_zeroize(self, sizeof(vscf_recipient_cipher_t));
    }
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
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_recipient_cipher_delete(vscf_recipient_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_recipient_cipher_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
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

    ++self->refcnt;

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
    VSCF_ASSERT_PTR(self->random == NULL);

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
vscf_recipient_cipher_use_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = vscf_impl_shallow_copy(cipher);
}

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT_PTR(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = cipher;
}

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_cipher(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->cipher);
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

    vscf_key_recipient_list_destroy(&self->key_recipients);
    vsc_buffer_destroy(&self->decryption_recipient_id);
    vscf_impl_destroy(&self->decryption_key);
    vsc_buffer_destroy(&self->decryption_password);
    vscf_message_info_destroy(&self->message_info);
    vscf_message_info_der_serializer_destroy(&self->message_info_der_serializer);
}

//
//  Setup dependencies with default values.
//
VSCF_PUBLIC void
vscf_recipient_cipher_setup_defaults(vscf_recipient_cipher_t *self) {

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_ctr_drbg_setup_defaults(random);
        self->random = vscf_ctr_drbg_impl(random);
    }

    if (NULL == self->cipher) {
        self->cipher = vscf_aes256_gcm_impl(vscf_aes256_gcm_new());
    }
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
    VSCF_ASSERT(vscf_encrypt_is_implemented(public_key));

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
VSCF_PUBLIC vscf_error_t
vscf_recipient_cipher_start_encryption(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->cipher);

    vscf_error_t status = vscf_SUCCESS;

    //
    //  Generate cipher key and nonce.
    //
    vsc_buffer_t *cipher_key = NULL;
    vsc_buffer_t *cipher_nonce = NULL;

    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->cipher)));
    const size_t cipher_nonce_len =
            vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->cipher)));

    cipher_key = vsc_buffer_new_with_capacity(cipher_key_len);
    vsc_buffer_make_secure(cipher_key);

    status = vscf_random(self->random, cipher_key_len, cipher_key);
    if (status != vscf_SUCCESS) {
        goto failed_generate_cipher_key;
    }

    cipher_nonce = vsc_buffer_new_with_capacity(cipher_nonce_len);

    status = vscf_random(self->random, cipher_nonce_len, cipher_nonce);
    if (status != vscf_SUCCESS) {
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

        const size_t encrypted_key_len = vscf_encrypt_encrypted_len(recipient_public_key, cipher_key_len);
        vsc_buffer_t *encrypted_key = vsc_buffer_new_with_capacity(encrypted_key_len);
        status = vscf_encrypt(recipient_public_key, vsc_buffer_data(cipher_key), encrypted_key);

        if (status != vscf_SUCCESS) {
            vsc_buffer_destroy(&encrypted_key);
            goto failed_build_message_info;
        }

        vscf_impl_t *key_encryption_algorithm = vscf_alg_produce_alg_info(recipient_public_key);
        vscf_key_recipient_info_t *recipient_info = vscf_key_recipient_info_new_with_members(
                recipient_id, &key_encryption_algorithm, vsc_buffer_data(encrypted_key));

        vscf_message_info_add_key_recipient(self->message_info, &recipient_info);

        vsc_buffer_destroy(&encrypted_key);
    }

    //
    //  TODO: Add password recipients.
    //

    //
    //  Configure cipher key and nonce.
    //
    vscf_cipher_set_key(self->cipher, vsc_buffer_data(cipher_key));
    vscf_cipher_set_nonce(self->cipher, vsc_buffer_data(cipher_nonce));
    vscf_cipher_start_encryption(self->cipher);

    vsc_buffer_destroy(&cipher_key);
    vsc_buffer_destroy(&cipher_nonce);

    //
    //  Append cipher info to the message info.
    //
    vscf_impl_t *data_encryption_alg_info = vscf_alg_produce_alg_info(self->cipher);
    vscf_message_info_set_data_encryption_alg_info(self->message_info, &data_encryption_alg_info);

    return vscf_SUCCESS;

failed_build_message_info:
    vscf_message_info_clear_recipients(self->message_info);

failed_generate_cipher_nonce:
    vsc_buffer_destroy(&cipher_nonce);

failed_generate_cipher_key:
    vsc_buffer_destroy(&cipher_key);

    return status;
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
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_UNUSED(data_len);

    return vscf_cipher_encrypted_out_len(self->cipher, data_len);
}

//
//  Process encryption of a new portion of data.
//
VSCF_PUBLIC vscf_error_t
vscf_recipient_cipher_process_encryption(vscf_recipient_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_encryption_out_len(self, data.len));

    vscf_cipher_update(self->cipher, data, out);

    return vscf_SUCCESS;
}

//
//  Accomplish encryption.
//
VSCF_PUBLIC vscf_error_t
vscf_recipient_cipher_finish_encryption(vscf_recipient_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_encryption_out_len(self, 0));

    vscf_error_t status = vscf_cipher_finish(self->cipher, out);

    return status;
}

//
//  Initiate decryption process with a recipient private key.
//
VSCF_PUBLIC vscf_error_t
vscf_recipient_cipher_start_decryption_with_key(
        vscf_recipient_cipher_t *self, vsc_data_t recipient_id, vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_decrypt_is_implemented(private_key));
    //  TODO: This is STUB. Implement me.
    return vscf_error_BAD_ARGUMENTS;
}

//
//  Return buffer length required to hold output of the method
//  "process decryption" and method "finish" during decryption.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_decryption_out_len(vscf_recipient_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(data_len);
    //  TODO: This is STUB. Implement me.
    return 0;
}

//
//  Process with a new portion of data.
//  Return error if data can not be encrypted or decrypted.
//
VSCF_PUBLIC vscf_error_t
vscf_recipient_cipher_process_decryption(vscf_recipient_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    //  TODO: This is STUB. Implement me.
    return vscf_error_BAD_ARGUMENTS;
}

//
//  Accomplish decryption.
//
VSCF_PUBLIC vscf_error_t
vscf_recipient_cipher_finish_decryption(vscf_recipient_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    //  TODO: This is STUB. Implement me.
    return vscf_error_BAD_ARGUMENTS;
}