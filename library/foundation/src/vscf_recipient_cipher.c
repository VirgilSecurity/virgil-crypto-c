//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
#include "vscf_recipient_cipher_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_cipher_auth.h"
#include "vscf_decrypt.h"
#include "vscf_encrypt.h"
#include "vscf_kdf.h"
#include "vscf_key_cipher.h"
#include "vscf_key_signer.h"
#include "vscf_private_key.h"
#include "vscf_public_key.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_key_recipient_list.h"
#include "vscf_aes256_gcm.h"
#include "vscf_ctr_drbg.h"
#include "vscf_alg_factory.h"
#include "vscf_key_alg_factory.h"
#include "vscf_sha512.h"
#include "vscf_hkdf.h"
#include "vscf_random_padding.h"
#include "vscf_message_info_der_serializer_internal.h"

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
//  Configure decryption symmetric cipher with given key and
//  nonce that is restored from the message info or derived from the key.
//
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
//  Deserialize given message info from the given data or extracted data.
//
static vscf_status_t
vscf_recipient_cipher_unpack_message_info(vscf_recipient_cipher_t *self, vsc_data_t message_info) VSCF_NODISCARD;

//
//  Deserialize given message info footer from the given data or extracted data.
//
static vscf_status_t
vscf_recipient_cipher_unpack_message_info_footer(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

static vscf_status_t
vscf_recipient_cipher_extract_message_info(vscf_recipient_cipher_t *self, vsc_data_t data) VSCF_NODISCARD;

//
//  For signed encryption set serialized footer info as
//  cipher additional data for AEAD ciphers.
//
static void
vscf_recipient_cipher_set_cipher_auth_data(vscf_recipient_cipher_t *self, vscf_impl_t *cipher);

//
//  Sign data digest.
//  Populate message info footer.
//  Encrypt message info footer.
//
static vscf_status_t
vscf_recipient_cipher_accomplish_signed_encryption(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

//
//  Calculate data digest.
//
static void
vscf_recipient_cipher_accomplish_verified_decryption(vscf_recipient_cipher_t *self);

//
//  Derive keys and nonces from given master.
//
static void
vscf_recipient_cipher_derive_decryption_cipher_keys_and_nonces(vscf_recipient_cipher_t *self, vsc_data_t master_key);

static void
vscf_recipient_cipher_configure_verifier_hash(vscf_recipient_cipher_t *self);

static vsc_data_t
vscf_recipient_cipher_data_derived_key(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher);

static vsc_data_t
vscf_recipient_cipher_data_derived_nonce(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher);

static vsc_data_t
vscf_recipient_cipher_footer_derived_key(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher);

static vsc_data_t
vscf_recipient_cipher_footer_derived_nonce(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher);

//
//  Setup default algorithms required for encryption.
//
static vscf_status_t
vscf_recipient_cipher_setup_encryption_defaults(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

static vscf_status_t
vscf_recipient_cipher_configure_encryption_cipher(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

static vscf_status_t
vscf_recipient_cipher_configure_kdf_feeded_encryption_cipher(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

static vscf_status_t
vscf_recipient_cipher_encrypt_cipher_key_for_recipients(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

static vsc_data_t
vscf_recipient_cipher_filter_message_info_footer(vscf_recipient_cipher_t *self, vsc_data_t data);

static void
vscf_recipient_cipher_decrypt_chunk(vscf_recipient_cipher_t *self, vsc_data_t data, vsc_buffer_t *out);

//
//  Add information related to encryption to a message info.
//
static vscf_status_t
vscf_recipient_cipher_update_message_info_for_encryption(vscf_recipient_cipher_t *self) VSCF_NODISCARD;

//
//  Configure padding cipher with given padding and cipher.
//
static void
vscf_recipient_cipher_configure_padding_cipher(vscf_recipient_cipher_t *self, vscf_impl_t *padding,
        vscf_impl_t *cipher);

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

    vscf_recipient_cipher_release_random(self);
    vscf_recipient_cipher_release_encryption_cipher(self);
    vscf_recipient_cipher_release_encryption_padding(self);
    vscf_recipient_cipher_release_padding_params(self);
    vscf_recipient_cipher_release_signer_hash(self);

    vscf_recipient_cipher_cleanup_ctx(self);

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
vscf_recipient_cipher_delete(const vscf_recipient_cipher_t *self) {

    vscf_recipient_cipher_t *local_self = (vscf_recipient_cipher_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vscf_recipient_cipher_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
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
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCF_PUBLIC const vscf_recipient_cipher_t *
vscf_recipient_cipher_shallow_copy_const(const vscf_recipient_cipher_t *self) {

    return vscf_recipient_cipher_shallow_copy((vscf_recipient_cipher_t *)self);
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

//
//  Setup dependency to the interface 'padding' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_encryption_padding(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_padding) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encryption_padding);
    VSCF_ASSERT(self->encryption_padding == NULL);

    VSCF_ASSERT(vscf_padding_is_implemented(encryption_padding));

    self->encryption_padding = vscf_impl_shallow_copy(encryption_padding);
}

//
//  Setup dependency to the interface 'padding' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_encryption_padding(vscf_recipient_cipher_t *self, vscf_impl_t *encryption_padding) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encryption_padding);
    VSCF_ASSERT(self->encryption_padding == NULL);

    VSCF_ASSERT(vscf_padding_is_implemented(encryption_padding));

    self->encryption_padding = encryption_padding;
}

//
//  Release dependency to the interface 'padding'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_encryption_padding(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->encryption_padding);
}

//
//  Setup dependency to the class 'padding params' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_padding_params(vscf_recipient_cipher_t *self, vscf_padding_params_t *padding_params) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding_params);
    VSCF_ASSERT(self->padding_params == NULL);

    self->padding_params = vscf_padding_params_shallow_copy(padding_params);
}

//
//  Setup dependency to the class 'padding params' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_padding_params(vscf_recipient_cipher_t *self, vscf_padding_params_t *padding_params) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding_params);
    VSCF_ASSERT(self->padding_params == NULL);

    self->padding_params = padding_params;
}

//
//  Release dependency to the class 'padding params'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_padding_params(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_padding_params_destroy(&self->padding_params);
}

//
//  Setup dependency to the interface 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_recipient_cipher_use_signer_hash(vscf_recipient_cipher_t *self, vscf_impl_t *signer_hash) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signer_hash);
    VSCF_ASSERT(self->signer_hash == NULL);

    VSCF_ASSERT(vscf_hash_is_implemented(signer_hash));

    self->signer_hash = vscf_impl_shallow_copy(signer_hash);
}

//
//  Setup dependency to the interface 'hash' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_recipient_cipher_take_signer_hash(vscf_recipient_cipher_t *self, vscf_impl_t *signer_hash) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signer_hash);
    VSCF_ASSERT(self->signer_hash == NULL);

    VSCF_ASSERT(vscf_hash_is_implemented(signer_hash));

    self->signer_hash = signer_hash;
}

//
//  Release dependency to the interface 'hash'.
//
VSCF_PUBLIC void
vscf_recipient_cipher_release_signer_hash(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->signer_hash);
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
    self->master_key = vsc_buffer_new();
    vsc_buffer_make_secure(self->master_key);
    self->derived_keys = vsc_buffer_new();
    vsc_buffer_make_secure(self->derived_keys);
    self->is_signed_operation = false;
    self->padding_params = vscf_padding_params_new();
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

    vsc_buffer_destroy(&self->data_digest);
    vsc_buffer_destroy(&self->master_key);
    vsc_buffer_destroy(&self->derived_keys);
    vsc_buffer_destroy(&self->decryption_password);
    vsc_buffer_destroy(&self->decryption_recipient_id);
    vsc_buffer_destroy(&self->message_info_footer_enc);
    vscf_impl_destroy(&self->verifier_hash);
    vscf_impl_destroy(&self->decryption_cipher);
    vscf_impl_destroy(&self->decryption_padding);
    vscf_impl_delete(self->decryption_recipient_key);
    vscf_key_recipient_list_destroy(&self->key_recipients);
    vscf_signer_list_destroy(&self->signers);
    vscf_message_info_der_serializer_destroy(&self->message_info_der_serializer);
    vscf_message_info_destroy(&self->message_info);
    vscf_message_info_footer_destroy(&self->message_info_footer);
    vscf_padding_cipher_destroy(&self->padding_cipher);
}

//
//  Return true if a key recipient with a given id has been added.
//  Note, operation has O(N) time complexity.
//
VSCF_PUBLIC bool
vscf_recipient_cipher_has_key_recipient(const vscf_recipient_cipher_t *self, vsc_data_t recipient_id) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(recipient_id));

    for (const vscf_key_recipient_list_t *curr = self->key_recipients;
            curr != NULL && vscf_key_recipient_list_has_key_recipient(curr);
            curr = vscf_key_recipient_list_next(curr)) {

        vsc_data_t curr_recipient_id = vscf_key_recipient_list_recipient_id(curr);
        if (vsc_data_equal(recipient_id, curr_recipient_id)) {
            return true;
        }
    }

    return false;
}

//
//  Add recipient defined with id and public key.
//
VSCF_PUBLIC void
vscf_recipient_cipher_add_key_recipient(
        vscf_recipient_cipher_t *self, vsc_data_t recipient_id, const vscf_impl_t *public_key) {

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
//  Add identifier and private key to sign initial plain text.
//  Return error if the private key can not sign.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_add_signer(vscf_recipient_cipher_t *self, vsc_data_t signer_id, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(signer_id));
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *signer = vscf_key_alg_factory_create_from_key(private_key, self->random, &error);

    if (vscf_error_has_error(&error)) {
        return vscf_error_status(&error);
    }

    const bool can_sign = vscf_key_signer_is_implemented(signer) && vscf_key_signer_can_sign(signer, private_key);
    vscf_impl_destroy(&signer);
    if (!can_sign) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    if (NULL == self->signers) {
        self->signers = vscf_signer_list_new();
    }

    vscf_signer_list_add(self->signers, signer_id, private_key);

    return vscf_status_SUCCESS;
}

//
//  Remove all signers.
//
VSCF_PUBLIC void
vscf_recipient_cipher_clear_signers(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    if (self->signers) {
        vscf_signer_list_clear(self->signers);
    }
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
//  Start encryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_encryption(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    //
    //  Setup defaults.
    //
    vscf_status_t status = vscf_recipient_cipher_setup_encryption_defaults(self);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    //
    //  Prepare cipher.
    //
    status = vscf_recipient_cipher_configure_encryption_cipher(self);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    if (self->encryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        vscf_padding_cipher_start_encryption(self->padding_cipher);
    } else {
        vscf_cipher_start_encryption(self->encryption_cipher);
    }

    //
    //  Update message info.
    //
    status = vscf_recipient_cipher_update_message_info_for_encryption(self);

    return status;
}

//
//  Start encryption process with known plain text size.
//
//  Precondition: At least one signer should be added.
//  Note, store message info footer as well.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_signed_encryption(vscf_recipient_cipher_t *self, size_t data_size) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signers);
    VSCF_ASSERT(vscf_signer_list_has_signer(self->signers));
    VSCF_ASSERT_PTR(self->message_info);

    //
    //  Setup defaults.
    //
    self->is_signed_operation = true;

    vscf_status_t status = vscf_recipient_cipher_setup_encryption_defaults(self);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    //
    //  Put footer info to the message info.
    //
    vscf_footer_info_t *footer_info = vscf_message_info_footer_info_m(self->message_info);
    vscf_footer_info_set_data_size(footer_info, data_size);

    vscf_signed_data_info_t *signed_data_info = vscf_footer_info_signed_data_info_m(footer_info);
    vscf_impl_t *signer_hash_alg_info = vscf_alg_produce_alg_info(self->signer_hash);
    vscf_signed_data_info_set_hash_alg_info(signed_data_info, &signer_hash_alg_info);

    //
    //  Prepare cipher.
    //
    status = vscf_recipient_cipher_configure_kdf_feeded_encryption_cipher(self);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    if (self->encryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        vscf_padding_cipher_start_encryption(self->padding_cipher);
    } else {
        vscf_cipher_start_encryption(self->encryption_cipher);
    }

    //
    //  Update message info.
    //
    status = vscf_recipient_cipher_update_message_info_for_encryption(self);

    //
    //  Start data hashing.
    //
    vscf_hash_start(self->signer_hash);

    //
    //  Remove master key.
    //
    vsc_buffer_release(self->master_key);

    return status;
}

//
//  Return buffer length required to hold message info returned by the
//  "pack message info" method.
//  Precondition: all recipients and custom parameters should be set.
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_message_info_len(const vscf_recipient_cipher_t *self) {

    VSCF_ASSERT(self);

    return vscf_message_info_der_serializer_serialized_len(self->message_info_der_serializer, self->message_info);
}

//
//  Return serialized message info to the buffer.
//
//  Precondition: this method should be called after "start encryption".
//  Precondition: this method should be called before "finish encryption".
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

    size_t out_len = 0;

    if (self->is_signed_operation && 0 == data_len) {
        out_len += vscf_recipient_cipher_message_info_footer_len(self);
    }

    if (self->encryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        out_len += vscf_padding_cipher_encrypted_out_len(self->padding_cipher, data_len);
    } else {
        out_len += vscf_cipher_encrypted_out_len(self->encryption_cipher, data_len);
    }

    return out_len;
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

    if (self->is_signed_operation) {
        vscf_hash_update(self->signer_hash, data);
    }

    if (self->encryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        vscf_padding_cipher_update(self->padding_cipher, data, out);
    } else {
        vscf_cipher_update(self->encryption_cipher, data, out);
    }

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

    vscf_status_t status = vscf_status_SUCCESS;

    if (self->is_signed_operation) {
        status = vscf_recipient_cipher_accomplish_signed_encryption(self);
        if (status != vscf_status_SUCCESS) {
            goto cleanup;
        }
    }

    if (self->encryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        status = vscf_padding_cipher_finish(self->padding_cipher, out);
    } else {
        status = vscf_cipher_finish(self->encryption_cipher, out);
    }

cleanup:
    vsc_buffer_release(self->derived_keys);

    return status;
}

//
//  Initiate decryption process with a recipient private key.
//  Message Info can be empty if it was embedded to encrypted data.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_decryption_with_key(vscf_recipient_cipher_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *private_key, vsc_data_t message_info) {

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
    vsc_buffer_destroy(&self->message_info_buffer);
    vscf_impl_destroy(&self->decryption_cipher);
    vscf_impl_delete(self->decryption_recipient_key);

    self->decryption_recipient_id = vsc_buffer_new_with_data(recipient_id);
    self->decryption_recipient_key = vscf_impl_shallow_copy_const(private_key);

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
//  Initiate decryption process with a recipient private key.
//  Message Info can be empty if it was embedded to encrypted data.
//  Message Info footer can be empty if it was embedded to encrypted data.
//  If footer was embedded, method "start decryption with key" can be used.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_start_verified_decryption_with_key(vscf_recipient_cipher_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *private_key, vsc_data_t message_info, vsc_data_t message_info_footer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vsc_data_is_valid(message_info));
    VSCF_ASSERT(vsc_data_is_valid(message_info_footer));

    self->is_signed_operation = true;

    vscf_status_t status =
            vscf_recipient_cipher_start_decryption_with_key(self, recipient_id, private_key, message_info);

    vsc_buffer_destroy(&self->message_info_footer_enc);
    if (!vsc_data_is_empty(message_info_footer)) {
        self->message_info_footer_enc = vsc_buffer_new_with_data(message_info_footer);
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

    size_t len = 0;

    if (self->message_info_buffer) {
        const size_t message_info_tail_len = vsc_buffer_len(self->message_info_buffer);
        len += message_info_tail_len;
    }

    if (self->decryption_padding) {
        len += vscf_padding_cipher_decrypted_out_len(self->padding_cipher, data_len);
    } else if (self->decryption_cipher) {
        len += vscf_cipher_decrypted_out_len(self->decryption_cipher, data_len);
    } else {
        //
        //  Underlying cipher is not known before message info is read, so return maximum at this point.
        //
        len += 16; // Maximum block length of any cipher in bytes.
        len += 16; // Maximum tag length of any cipher in bytes.
        if (data_len > 0) {
            len += data_len;
        } else {
            const size_t padding_tail_len = vscf_padding_params_frame_max(self->padding_params);
            len += padding_tail_len;
        }
    }

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
    case vscf_recipient_cipher_decryption_state_WAITING_MESSAGE_INFO: {
        vscf_status_t status = vscf_recipient_cipher_extract_message_info(self, data);
        if (status == vscf_status_SUCCESS && (self->message_info_buffer != NULL) &&
                (self->decryption_state == vscf_recipient_cipher_decryption_state_PROCESSING_DATA)) {

            VSCF_ASSERT(vsc_buffer_len(self->message_info_buffer) >= self->message_info_expected_len);
            size_t tail_len = vsc_buffer_len(self->message_info_buffer) - self->message_info_expected_len;
            vsc_data_t tail = vsc_data_slice_end(vsc_buffer_data(self->message_info_buffer), 0, tail_len);
            vscf_recipient_cipher_decrypt_chunk(self, tail, out);
            vsc_buffer_destroy(&self->message_info_buffer);
            self->message_info_expected_len = 0;
        }
        return status;
    }
    case vscf_recipient_cipher_decryption_state_PROCESSING_DATA: {
        vscf_recipient_cipher_decrypt_chunk(self, data, out);
        return vscf_status_SUCCESS;
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

    const size_t len_before = vsc_buffer_len(out);

    vscf_status_t status = vscf_status_SUCCESS;
    if (self->decryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        status = vscf_padding_cipher_finish(self->padding_cipher, out);
    } else {
        status = vscf_cipher_finish(self->decryption_cipher, out);
    }

    if (status != vscf_status_SUCCESS) {
        return status;
    }

    const size_t len_after = vsc_buffer_len(out);
    if (self->is_signed_operation) {
        const size_t written_len = len_after - len_before;
        vscf_hash_update(self->verifier_hash, vsc_data_slice_beg(vsc_buffer_data(out), len_before, written_len));
    }

    if (vscf_message_info_has_footer_info(self->message_info)) {
        status = vscf_recipient_cipher_unpack_message_info_footer(self);
    }

    vscf_impl_destroy(&self->decryption_cipher);

    if (self->is_signed_operation) {
        vscf_recipient_cipher_accomplish_verified_decryption(self);
    }

    vsc_buffer_release(self->derived_keys);

    return status;
}

//
//  Return true if data was signed by a sender.
//
//  Precondition: this method should be called after "finish decryption".
//
VSCF_PUBLIC bool
vscf_recipient_cipher_is_data_signed(const vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->is_signed_operation;
}

//
//  Return information about signers that sign data.
//
//  Precondition: this method should be called after "finish decryption".
//  Precondition: method "is data signed" returns true.
//
VSCF_PUBLIC const vscf_signer_info_list_t *
vscf_recipient_cipher_signer_infos(const vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->is_signed_operation);
    VSCF_ASSERT_PTR(self->message_info_footer);

    return vscf_message_info_footer_signer_infos(self->message_info_footer);
}

//
//  Verify given cipher info.
//
VSCF_PUBLIC bool
vscf_recipient_cipher_verify_signer_info(
        vscf_recipient_cipher_t *self, const vscf_signer_info_t *signer_info, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(vscf_message_info_has_footer_info(self->message_info));
    VSCF_ASSERT_PTR(signer_info);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    const vscf_impl_t *public_key_alg_info = vscf_key_alg_info(public_key);
    const vscf_impl_t *signer_alg_info = vscf_signer_info_signer_alg_info(signer_info);

    const vscf_footer_info_t *footer_info = vscf_message_info_footer_info(self->message_info);
    const vscf_signed_data_info_t *signed_data_info = vscf_footer_info_signed_data_info(footer_info);
    const vscf_alg_id_t hash_alg_id = vscf_alg_info_alg_id(vscf_signed_data_info_hash_alg_info(signed_data_info));

    if (vscf_alg_info_alg_id(public_key_alg_info) != vscf_alg_info_alg_id(signer_alg_info)) {
        //  TODO: Log error - mismatch signature algorithms
        return false;
    }

    vscf_impl_t *signer = vscf_key_alg_factory_create_from_key(public_key, self->random, &error);
    if (vscf_error_has_error(&error)) {
        //  TODO: Log underlying error.
        vscf_impl_destroy(&signer);
        return false;
    }

    if (!vscf_key_signer_is_implemented(signer) || !vscf_key_signer_can_verify(signer, public_key)) {
        //  TODO: Log error - vscf_status_ERROR_UNSUPPORTED_ALGORITHM
        vscf_impl_destroy(&signer);
        return false;
    }

    const vsc_data_t digest = vsc_buffer_data(self->data_digest);
    const vsc_data_t signature = vscf_signer_info_signature(signer_info);

    const bool is_verified = vscf_key_signer_verify_hash(signer, public_key, hash_alg_id, digest, signature);
    vscf_impl_destroy(&signer);
    return is_verified;
}

//
//  Configure decryption symmetric cipher with given key and
//  nonce that is restored from the message info or derived from the key.
//
//  Note, this method change decryption state.
//
static vscf_status_t
vscf_recipient_cipher_configure_decryption_cipher(vscf_recipient_cipher_t *self, vsc_data_t decryption_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);

    //
    //  Reset decryption state.
    //
    self->processed_encrypted_data_len = 0;

    //
    //  Restore decryption cipher.
    //
    vscf_impl_destroy(&self->decryption_cipher);
    const vscf_impl_t *cipher_alg_info = vscf_message_info_data_encryption_alg_info(self->message_info);
    self->decryption_cipher = vscf_alg_factory_create_cipher_from_info(cipher_alg_info);

    //
    //  Cipher KDF.
    //
    if (vscf_message_info_has_cipher_kdf_alg_info(self->message_info)) {
        vscf_recipient_cipher_derive_decryption_cipher_keys_and_nonces(self, decryption_key);

        vsc_data_t key = vscf_recipient_cipher_data_derived_key(self, self->decryption_cipher);
        vscf_cipher_set_key(self->decryption_cipher, key);

        vsc_data_t nonce = vscf_recipient_cipher_data_derived_nonce(self, self->decryption_cipher);
        vscf_cipher_set_nonce(self->decryption_cipher, nonce);
    } else {
        vscf_cipher_set_key(self->decryption_cipher, decryption_key);
    }

    //
    //  Cipher padding.
    //
    vscf_impl_destroy(&self->decryption_padding);
    if (vscf_message_info_has_cipher_padding_alg_info(self->message_info)) {
        const vscf_impl_t *padding_info = vscf_message_info_cipher_padding_alg_info(self->message_info);
        self->decryption_padding = vscf_alg_factory_create_padding_from_info(padding_info, self->random);
        if (NULL == self->decryption_padding) {
            return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
        }
        vscf_padding_configure(self->decryption_padding, self->padding_params);
        vscf_recipient_cipher_configure_padding_cipher(self, self->decryption_padding, self->decryption_cipher);
    }

    //
    //  Configure cipher additional data.
    //
    vscf_recipient_cipher_set_cipher_auth_data(self, self->decryption_cipher);

    //
    //  Start decryption.
    //
    if (self->decryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        vscf_padding_cipher_start_decryption(self->padding_cipher);
    } else {
        vscf_cipher_start_decryption(self->decryption_cipher);
    }

    //
    //  Configure verifier hash.
    //
    vscf_recipient_cipher_configure_verifier_hash(self);

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
//  Deserialize given message info from the given data or extracted data.
//
static vscf_status_t
vscf_recipient_cipher_unpack_message_info(vscf_recipient_cipher_t *self, vsc_data_t message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(message_info));
    VSCF_ASSERT_PTR(self->message_info_der_serializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_message_info_destroy(&self->message_info);
    self->message_info =
            vscf_message_info_der_serializer_deserialize(self->message_info_der_serializer, message_info, &error);

    return vscf_error_status(&error);
}

//
//  Deserialize given message info footer from the given data or extracted data.
//
static vscf_status_t
vscf_recipient_cipher_unpack_message_info_footer(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info_der_serializer);
    VSCF_ASSERT_PTR(self->decryption_cipher);

    vscf_message_info_footer_destroy(&self->message_info_footer);

    if (NULL == self->message_info_footer_enc) {
        return vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER;
    }

    //
    //  Decrypt footer.
    //
    vsc_data_t key = vscf_recipient_cipher_footer_derived_key(self, self->decryption_cipher);
    vscf_cipher_set_key(self->decryption_cipher, key);

    vsc_data_t nonce = vscf_recipient_cipher_footer_derived_nonce(self, self->decryption_cipher);
    vscf_cipher_set_nonce(self->decryption_cipher, nonce);

    if (vscf_cipher_auth_is_implemented(self->decryption_cipher)) {
        vscf_cipher_auth_set_auth_data(self->decryption_cipher, vsc_data_empty());
    }

    vsc_data_t enc_footer = vsc_buffer_data(self->message_info_footer_enc);

    const size_t plain_footer_len = vscf_decrypt_decrypted_len(self->decryption_cipher, enc_footer.len);
    vsc_buffer_t *plain_footer = vsc_buffer_new_with_capacity(plain_footer_len);
    const vscf_status_t status = vscf_decrypt(self->decryption_cipher, enc_footer, plain_footer);

    if (status != vscf_status_SUCCESS) {
        //  TODO: Log underlying error.
        vsc_buffer_destroy(&plain_footer);
        return vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER;
    }

    vscf_error_t error;
    vscf_error_reset(&error);

    self->message_info_footer = vscf_message_info_der_serializer_deserialize_footer(
            self->message_info_der_serializer, vsc_buffer_data(plain_footer), &error);

    vsc_buffer_destroy(&plain_footer);

    return vscf_error_status(&error);
}

//
//  Return buffer length required to hold message footer returned by the
//  "pack message footer" method.
//
//  Precondition: this method should be called after "finish encryption".
//
VSCF_PUBLIC size_t
vscf_recipient_cipher_message_info_footer_len(const vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->message_info_footer) {
        return 0;
    }

    const size_t plain_len = vscf_message_info_der_serializer_serialized_footer_len(
            self->message_info_der_serializer, self->message_info_footer);

    const size_t encrypted_len = vscf_encrypt_encrypted_len(self->encryption_cipher, plain_len);

    return encrypted_len;
}

//
//  Return serialized message info footer to the buffer.
//
//  Precondition: this method should be called after "finish encryption".
//
//  Note, store message info to use it for verified decryption process,
//  or place it at the encrypted data ending (embedding).
//
//  Return message info footer - signers public information, etc.
//
VSCF_PUBLIC vscf_status_t
vscf_recipient_cipher_pack_message_info_footer(vscf_recipient_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_recipient_cipher_message_info_footer_len(self));

    if (NULL == self->message_info_footer) {
        return vscf_status_SUCCESS;
    }

    const size_t plain_footer_len = vscf_message_info_der_serializer_serialized_footer_len(
            self->message_info_der_serializer, self->message_info_footer);

    vsc_buffer_t *plain_footer = vsc_buffer_new_with_capacity(plain_footer_len);

    vscf_message_info_der_serializer_serialize_footer(
            self->message_info_der_serializer, self->message_info_footer, plain_footer);

    const vscf_status_t status = vscf_encrypt(self->encryption_cipher, vsc_buffer_data(plain_footer), out);

    vsc_buffer_destroy(&plain_footer);

    return status;
}

static vscf_status_t
vscf_recipient_cipher_extract_message_info(vscf_recipient_cipher_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info_der_serializer);
    VSCF_ASSERT(vsc_data_is_valid(data));

    VSCF_ASSERT(self->decryption_state == vscf_recipient_cipher_decryption_state_WAITING_MESSAGE_INFO);
    VSCF_ASSERT(self->message_info_buffer);

    vsc_buffer_append_data(self->message_info_buffer, data);

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

//
//  For signed encryption set serialized footer info as
//  cipher additional data for AEAD ciphers.
//
static void
vscf_recipient_cipher_set_cipher_auth_data(vscf_recipient_cipher_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(cipher);

    if (!vscf_cipher_auth_is_implemented(cipher)) {
        return;
    }

    if (!vscf_message_info_has_footer_info(self->message_info)) {
        return;
    }

    const vscf_footer_info_t *footer_info = vscf_message_info_footer_info(self->message_info);
    if (!vscf_footer_info_has_signed_data_info(footer_info)) {
        return;
    }

    const vscf_signed_data_info_t *signed_data_info = vscf_footer_info_signed_data_info(footer_info);

    const size_t serialized_signed_data_info_len = vscf_message_info_der_serializer_serialized_signed_data_info_len(
            self->message_info_der_serializer, signed_data_info);

    vsc_buffer_t *serialized_signed_data_info = vsc_buffer_new_with_capacity(serialized_signed_data_info_len);

    vscf_message_info_der_serializer_serialize_signed_data_info(
            self->message_info_der_serializer, signed_data_info, serialized_signed_data_info);

    vscf_cipher_auth_set_auth_data(cipher, vsc_buffer_data(serialized_signed_data_info));

    vsc_buffer_destroy(&serialized_signed_data_info);
}

//
//  Sign data digest.
//  Populate message info footer.
//  Encrypt message info footer.
//
static vscf_status_t
vscf_recipient_cipher_accomplish_signed_encryption(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->is_signed_operation);
    VSCF_ASSERT_PTR(self->signer_hash);
    VSCF_ASSERT_PTR(self->message_info_footer);
    VSCF_ASSERT(vscf_signer_list_has_signer(self->signers));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Cleanup previous data.
    //
    vscf_message_info_footer_clear_signer_infos(self->message_info_footer);

    //
    //  Calculate data digest.
    //
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_hash_digest_len(vscf_hash_api(self->signer_hash)));
    vscf_hash_finish(self->signer_hash, digest);
    const vscf_alg_id_t hash_alg_id = vscf_alg_alg_id(self->signer_hash);

    //
    //  Sign digest and add signer infos.
    //
    vscf_impl_t *signer = NULL;
    vsc_buffer_t *signature = NULL;
    const vscf_signer_list_t *signer_iterator = self->signers;
    do {
        vsc_data_t signer_id = vscf_signer_list_signer_id(signer_iterator);
        const vscf_impl_t *signer_private_key = vscf_signer_list_signer_private_key(signer_iterator);

        signer = vscf_key_alg_factory_create_from_key(signer_private_key, self->random, &error);
        if (vscf_error_has_error(&error)) {
            goto sign_failed;
        }

        signature = vsc_buffer_new_with_capacity(vscf_key_signer_signature_len(signer, signer_private_key));

        const vscf_status_t sign_status =
                vscf_key_signer_sign_hash(signer, signer_private_key, hash_alg_id, vsc_buffer_data(digest), signature);

        if (sign_status != vscf_status_SUCCESS) {
            vscf_error_update(&error, sign_status);
            goto sign_failed;
        }

        vscf_impl_t *signer_alg_info = vscf_impl_shallow_copy((vscf_impl_t *)vscf_key_alg_info(signer_private_key));
        vscf_signer_info_t *signer_info = vscf_signer_info_new_with_members(signer_id, &signer_alg_info, &signature);
        vscf_message_info_footer_add_signer_info(self->message_info_footer, &signer_info);
    } while ((signer_iterator = vscf_signer_list_next(signer_iterator)) != NULL);

    vscf_message_info_footer_set_signer_digest(self->message_info_footer, &digest);

    //
    //  Configure encryption cipher for encrypting footer.
    //
    vsc_data_t key = vscf_recipient_cipher_footer_derived_key(self, self->encryption_cipher);
    vscf_cipher_set_key(self->encryption_cipher, key);

    vsc_data_t nonce = vscf_recipient_cipher_footer_derived_nonce(self, self->encryption_cipher);
    vscf_cipher_set_nonce(self->encryption_cipher, nonce);

    if (vscf_cipher_auth_is_implemented(self->encryption_cipher)) {
        vscf_cipher_auth_set_auth_data(self->encryption_cipher, vsc_data_empty());
    }

    goto cleanup;

sign_failed:
    vsc_buffer_destroy(&digest);
    vsc_buffer_destroy(&signature);

cleanup:
    vscf_impl_destroy(&signer);

    return vscf_error_status(&error);
}

//
//  Calculate data digest.
//
static void
vscf_recipient_cipher_accomplish_verified_decryption(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->verifier_hash);

    vsc_buffer_destroy(&self->data_digest);
    const size_t digest_len = vscf_hash_digest_len(vscf_hash_api(self->verifier_hash));
    self->data_digest = vsc_buffer_new_with_capacity(digest_len);

    vscf_hash_finish(self->verifier_hash, self->data_digest);
}

//
//  Derive keys and nonces from given master.
//
static void
vscf_recipient_cipher_derive_decryption_cipher_keys_and_nonces(vscf_recipient_cipher_t *self, vsc_data_t master_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(self->decryption_cipher);
    VSCF_ASSERT(vscf_message_info_has_cipher_kdf_alg_info(self->message_info));
    VSCF_ASSERT(vsc_data_is_valid(master_key));

    const size_t cipher_key_len =
            vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->decryption_cipher)));

    const size_t cipher_nonce_len =
            vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->decryption_cipher)));

    const size_t derived_keys_len = 2 * cipher_key_len + 2 * cipher_nonce_len;
    vsc_buffer_release(self->derived_keys);
    vsc_buffer_alloc(self->derived_keys, derived_keys_len);

    const vscf_impl_t *cipher_kdf_alg_info = vscf_message_info_cipher_kdf_alg_info(self->message_info);
    vscf_impl_t *cipher_kdf = vscf_alg_factory_create_kdf_from_info(cipher_kdf_alg_info);

    vscf_kdf_derive(cipher_kdf, master_key, derived_keys_len, self->derived_keys);

    vscf_impl_destroy(&cipher_kdf);
}

static void
vscf_recipient_cipher_configure_verifier_hash(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);

    if (!vscf_message_info_has_footer_info(self->message_info)) {
        return;
    }

    const vscf_footer_info_t *footer_info = vscf_message_info_footer_info(self->message_info);
    if (!vscf_footer_info_has_signed_data_info(footer_info)) {
        return;
    }

    const vscf_signed_data_info_t *signed_data_info = vscf_footer_info_signed_data_info(footer_info);
    const vscf_impl_t *hash_alg_info = vscf_signed_data_info_hash_alg_info(signed_data_info);

    vscf_impl_destroy(&self->verifier_hash);
    self->verifier_hash = vscf_alg_factory_create_hash_from_info(hash_alg_info);
    vscf_hash_start(self->verifier_hash);

    self->is_signed_operation = true;
}

static vsc_data_t
vscf_recipient_cipher_data_derived_key(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->derived_keys));
    VSCF_ASSERT_PTR(cipher);

    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t cipher_nonce_len = vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t derived_keys_len = 2 * cipher_key_len + 2 * cipher_nonce_len;

    VSCF_ASSERT(vsc_buffer_len(self->derived_keys) == derived_keys_len);

    return vsc_data_slice_beg(vsc_buffer_data(self->derived_keys), 0, cipher_key_len);
}

static vsc_data_t
vscf_recipient_cipher_data_derived_nonce(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->derived_keys));
    VSCF_ASSERT_PTR(cipher);

    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t cipher_nonce_len = vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t derived_keys_len = 2 * cipher_key_len + 2 * cipher_nonce_len;

    VSCF_ASSERT(vsc_buffer_len(self->derived_keys) == derived_keys_len);

    return vsc_data_slice_beg(vsc_buffer_data(self->derived_keys), cipher_key_len, cipher_nonce_len);
}

static vsc_data_t
vscf_recipient_cipher_footer_derived_key(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->derived_keys));
    VSCF_ASSERT_PTR(cipher);

    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t cipher_nonce_len = vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t derived_keys_len = 2 * cipher_key_len + 2 * cipher_nonce_len;

    VSCF_ASSERT(vsc_buffer_len(self->derived_keys) == derived_keys_len);

    return vsc_data_slice_beg(vsc_buffer_data(self->derived_keys), cipher_key_len + cipher_nonce_len, cipher_key_len);
}

static vsc_data_t
vscf_recipient_cipher_footer_derived_nonce(const vscf_recipient_cipher_t *self, const vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->derived_keys));
    VSCF_ASSERT_PTR(cipher);

    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t cipher_nonce_len = vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(cipher)));

    const size_t derived_keys_len = 2 * cipher_key_len + 2 * cipher_nonce_len;

    VSCF_ASSERT(vsc_buffer_len(self->derived_keys) == derived_keys_len);

    return vsc_data_slice_beg(
            vsc_buffer_data(self->derived_keys), 2 * cipher_key_len + cipher_nonce_len, cipher_nonce_len);
}

//
//  Setup default algorithms required for encryption.
//
static vscf_status_t
vscf_recipient_cipher_setup_encryption_defaults(vscf_recipient_cipher_t *self) {

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

    if (self->is_signed_operation) {
        if (NULL == self->signer_hash) {
            self->signer_hash = vscf_sha512_impl(vscf_sha512_new());
        }

        if (NULL == self->message_info_footer) {
            self->message_info_footer = vscf_message_info_footer_new();
        }
    }

    if (self->encryption_padding != NULL) {
        vscf_padding_configure(self->encryption_padding, self->padding_params);
        vscf_recipient_cipher_configure_padding_cipher(self, self->encryption_padding, self->encryption_cipher);
    }

    return vscf_status_SUCCESS;
}

static vscf_status_t
vscf_recipient_cipher_configure_encryption_cipher(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->encryption_cipher);

    //
    //  Generate cipher key.
    //
    const size_t cipher_key_len =
            vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->encryption_cipher)));
    vsc_buffer_release(self->master_key);
    vsc_buffer_alloc(self->master_key, cipher_key_len);

    vscf_status_t status = vscf_random(self->random, cipher_key_len, self->master_key);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    //
    //  Generate cipher nonce.
    //
    const size_t cipher_nonce_len =
            vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->encryption_cipher)));
    vsc_buffer_t *cipher_nonce = vsc_buffer_new_with_capacity(cipher_nonce_len);

    status = vscf_random(self->random, cipher_nonce_len, cipher_nonce);
    if (status != vscf_status_SUCCESS) {
        vsc_buffer_release(self->master_key);
        vsc_buffer_destroy(&cipher_nonce);
        return status;
    }

    //
    //  Configure cipher.
    //
    vscf_cipher_set_key(self->encryption_cipher, vsc_buffer_data(self->master_key));
    vscf_cipher_set_nonce(self->encryption_cipher, vsc_buffer_data(cipher_nonce));
    vsc_buffer_destroy(&cipher_nonce);

    if (vscf_cipher_auth_is_implemented(self->encryption_cipher)) {
        vscf_cipher_auth_set_auth_data(self->encryption_cipher, vsc_data_empty());
    }

    return vscf_status_SUCCESS;
}

static vscf_status_t
vscf_recipient_cipher_configure_kdf_feeded_encryption_cipher(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->encryption_cipher);

    //
    //  Generate cipher key material (32 random bytes) and derive 2 cipher
    //  keys and 2 cipher nonces.
    //
    vsc_buffer_release(self->master_key);
    vsc_buffer_alloc(self->master_key, 32);
    const vscf_status_t status = vscf_random(self->random, vsc_buffer_unused_len(self->master_key), self->master_key);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    //
    //  Reconfigure cipher KDF.
    //
    const size_t cipher_key_len =
            vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->encryption_cipher)));

    const size_t cipher_nonce_len =
            vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->encryption_cipher)));

    const size_t derived_keys_len = 2 * cipher_key_len + 2 * cipher_nonce_len;
    vsc_buffer_release(self->derived_keys);
    vsc_buffer_alloc(self->derived_keys, derived_keys_len);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    vscf_hkdf_derive(hkdf, vsc_buffer_data(self->master_key), derived_keys_len, self->derived_keys);

    //
    //  Configure cipher.
    //
    vsc_data_t key = vscf_recipient_cipher_data_derived_key(self, self->encryption_cipher);
    vscf_cipher_set_key(self->encryption_cipher, key);

    vsc_data_t nonce = vscf_recipient_cipher_data_derived_nonce(self, self->encryption_cipher);
    vscf_cipher_set_nonce(self->encryption_cipher, nonce);

    vscf_recipient_cipher_set_cipher_auth_data(self, self->encryption_cipher);

    //
    //  Pass KDF alg to the message info.
    //
    vscf_impl_t *cipher_kdf_alg_info = vscf_hkdf_produce_alg_info(hkdf);
    vscf_message_info_set_cipher_kdf_alg_info(self->message_info, &cipher_kdf_alg_info);
    vscf_hkdf_destroy(&hkdf);

    return vscf_status_SUCCESS;
}

static vscf_status_t
vscf_recipient_cipher_encrypt_cipher_key_for_recipients(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    //
    //  Process key recipients.
    //
    vscf_message_info_clear_recipients(self->message_info);

    for (const vscf_key_recipient_list_t *curr = self->key_recipients; curr != NULL;
            curr = vscf_key_recipient_list_next(curr)) {

        vscf_error_t error;
        vscf_error_reset(&error);

        vsc_data_t recipient_id = vscf_key_recipient_list_recipient_id(curr);
        const vscf_impl_t *recipient_public_key = vscf_key_recipient_list_recipient_public_key(curr);

        vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(recipient_public_key, self->random, &error);
        if (vscf_error_has_error(&error)) {
            return vscf_error_status(&error);
        }
        VSCF_ASSERT(vscf_key_cipher_is_implemented(key_alg));

        vsc_data_t cipher_key = vsc_buffer_data(self->master_key);

        const size_t encrypted_key_len = vscf_key_cipher_encrypted_len(key_alg, recipient_public_key, cipher_key.len);
        vsc_buffer_t *encrypted_key = vsc_buffer_new_with_capacity(encrypted_key_len);
        error.status = vscf_key_cipher_encrypt(key_alg, recipient_public_key, cipher_key, encrypted_key);
        vscf_impl_destroy(&key_alg);

        if (vscf_error_has_error(&error)) {
            vsc_buffer_destroy(&encrypted_key);
            return vscf_error_status(&error);
        }

        vscf_key_recipient_info_t *recipient_info = vscf_key_recipient_info_new_with_buffer(
                recipient_id, vscf_key_alg_info(recipient_public_key), &encrypted_key);

        vscf_message_info_add_key_recipient(self->message_info, &recipient_info);
    }

    //
    //  TODO: Process password recipients
    //

    return vscf_status_SUCCESS;
}

static vsc_data_t
vscf_recipient_cipher_filter_message_info_footer(vscf_recipient_cipher_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->decryption_cipher);

    if (!vscf_message_info_has_footer_info(self->message_info)) {
        return data;
    }

    const vscf_footer_info_t *footer_info = vscf_message_info_footer_info(self->message_info);
    const size_t data_size = vscf_footer_info_data_size(footer_info);
    const size_t expected_encrypted_data_length =
            vscf_encrypt_precise_encrypted_len(self->decryption_cipher, data_size);

    //  Data was incompletely proceeded and footer is unreachable at this moment.
    if (self->processed_encrypted_data_len + data.len <= expected_encrypted_data_length) {
        self->processed_encrypted_data_len += data.len;
        return data;
    }

    if (NULL == self->message_info_footer_enc) {
        self->message_info_footer_enc = vsc_buffer_new_with_capacity(data.len);
    }

    //  Data was completely proceeded, so accumulate footer.
    if (self->processed_encrypted_data_len >= expected_encrypted_data_length) {
        vsc_buffer_append_data(self->message_info_footer_enc, data);
        return vsc_data_empty();
    }

    //  Given data contains data and footer, so split it.
    VSCF_ASSERT(expected_encrypted_data_length > self->processed_encrypted_data_len);
    const size_t enc_data_len = expected_encrypted_data_length - self->processed_encrypted_data_len;
    vsc_data_t enc_data = vsc_data_slice_beg(data, 0, enc_data_len);
    vsc_data_t footer_data = vsc_data_slice_beg(data, enc_data_len, data.len - enc_data_len);

    vsc_buffer_append_data(self->message_info_footer_enc, footer_data);
    self->processed_encrypted_data_len += enc_data_len;
    return enc_data;
}

static void
vscf_recipient_cipher_decrypt_chunk(vscf_recipient_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->message_info);
    VSCF_ASSERT_PTR(self->decryption_cipher);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    //
    //  Filter footer.
    //
    vsc_data_t filtered_data = vscf_recipient_cipher_filter_message_info_footer(self, data);

    if (vsc_data_is_empty(filtered_data)) {
        return;
    }

    const size_t len_before = vsc_buffer_len(out);

    if (self->decryption_padding) {
        VSCF_ASSERT_PTR(self->padding_cipher);
        vscf_padding_cipher_update(self->padding_cipher, filtered_data, out);
    } else {
        vscf_cipher_update(self->decryption_cipher, filtered_data, out);
    }

    const size_t len_after = vsc_buffer_len(out);
    const size_t written_len = len_after - len_before;
    if (self->is_signed_operation) {
        vscf_hash_update(self->verifier_hash, vsc_data_slice_beg(vsc_buffer_data(out), len_before, written_len));
    }
}

//
//  Add information related to encryption to a message info.
//
static vscf_status_t
vscf_recipient_cipher_update_message_info_for_encryption(vscf_recipient_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    //
    //  Put cipher info to the message info.
    //
    vscf_impl_t *data_encryption_alg_info = vscf_alg_produce_alg_info(self->encryption_cipher);
    vscf_message_info_set_data_encryption_alg_info(self->message_info, &data_encryption_alg_info);

    //
    //  Put cipher padding to the message info.
    //
    if (self->encryption_padding) {
        vscf_impl_t *padding_alg_info = vscf_alg_produce_alg_info(self->encryption_padding);
        vscf_message_info_set_cipher_padding_alg_info(self->message_info, &padding_alg_info);

        if (self->is_signed_operation) {
            //
            //  Adjust plaintext size due to a padding.
            //
            vscf_footer_info_t *footer_info = vscf_message_info_footer_info_m(self->message_info);
            const size_t data_size = vscf_footer_info_data_size(footer_info);
            const size_t padded_data_size = vscf_padding_padded_data_len(self->encryption_padding, data_size);
            vscf_footer_info_set_data_size(footer_info, padded_data_size);
        }
    }

    //
    //  Put recipients info to the message info.
    //
    const vscf_status_t status = vscf_recipient_cipher_encrypt_cipher_key_for_recipients(self);

    return status;
}

//
//  Configure padding cipher with given padding and cipher.
//
static void
vscf_recipient_cipher_configure_padding_cipher(
        vscf_recipient_cipher_t *self, vscf_impl_t *padding, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding);
    VSCF_ASSERT_PTR(cipher);

    if (NULL == self->padding_cipher) {
        self->padding_cipher = vscf_padding_cipher_new();
    }

    vscf_padding_cipher_release_padding(self->padding_cipher);
    vscf_padding_cipher_use_padding(self->padding_cipher, padding);

    vscf_padding_cipher_release_cipher(self->padding_cipher);
    vscf_padding_cipher_use_cipher(self->padding_cipher, cipher);
}
