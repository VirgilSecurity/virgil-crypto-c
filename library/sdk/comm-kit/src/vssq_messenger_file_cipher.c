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
//  Segment file encryption and decryption.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_file_cipher.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_file_cipher_defs.h"
#include "vssq_error.h"

#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/common/vsc_str.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_file_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_file_cipher_init_ctx(vssq_messenger_file_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_file_cipher_cleanup_ctx(vssq_messenger_file_cipher_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_file_cipher_did_setup_random(vssq_messenger_file_cipher_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_file_cipher_did_release_random(vssq_messenger_file_cipher_t *self);

static const char cipher_recipient_id_chars[] = "file-cipher";

static const vsc_str_t cipher_recipient_id = {
    cipher_recipient_id_chars,
    sizeof(cipher_recipient_id_chars) - 1
};

//
//  Return size of 'vssq_messenger_file_cipher_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_ctx_size(void) {

    return sizeof(vssq_messenger_file_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_init(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_file_cipher_t));

    self->refcnt = 1;

    vssq_messenger_file_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_cleanup(vssq_messenger_file_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_file_cipher_release_random(self);

    vssq_messenger_file_cipher_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_file_cipher_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_file_cipher_t *
vssq_messenger_file_cipher_new(void) {

    vssq_messenger_file_cipher_t *self = (vssq_messenger_file_cipher_t *) vssq_alloc(sizeof (vssq_messenger_file_cipher_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_file_cipher_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_delete(const vssq_messenger_file_cipher_t *self) {

    vssq_messenger_file_cipher_t *local_self = (vssq_messenger_file_cipher_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSQ_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSQ_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssq_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssq_messenger_file_cipher_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_file_cipher_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_destroy(vssq_messenger_file_cipher_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_file_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_file_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_file_cipher_t *
vssq_messenger_file_cipher_shallow_copy(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_file_cipher_t *
vssq_messenger_file_cipher_shallow_copy_const(const vssq_messenger_file_cipher_t *self) {

    return vssq_messenger_file_cipher_shallow_copy((vssq_messenger_file_cipher_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_use_random(vssq_messenger_file_cipher_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vssq_messenger_file_cipher_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_take_random(vssq_messenger_file_cipher_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vssq_messenger_file_cipher_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_file_cipher_release_random(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vssq_messenger_file_cipher_did_release_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_file_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_file_cipher_init_ctx(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);
    self->key_provider = vscf_key_provider_new();
    self->recipient_cipher = vscf_recipient_cipher_new();
    self->signer = vscf_signer_new();
    self->verifier = vscf_verifier_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_file_cipher_cleanup_ctx(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);
    vscf_key_provider_destroy(&self->key_provider);
    vscf_recipient_cipher_destroy(&self->recipient_cipher);
    vscf_signer_destroy(&self->signer);
    vscf_verifier_destroy(&self->verifier);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_file_cipher_did_setup_random(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);
    vscf_key_provider_release_random(self->key_provider);
    vscf_recipient_cipher_release_random(self->recipient_cipher);
    vscf_signer_release_random(self->signer);

    vscf_key_provider_use_random(self->key_provider, self->random);
    vscf_recipient_cipher_use_random(self->recipient_cipher, self->random);
    vscf_signer_use_random(self->signer, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_file_cipher_did_release_random(vssq_messenger_file_cipher_t *self) {

    vscf_key_provider_release_random(self->key_provider);
    vscf_recipient_cipher_release_random(self->recipient_cipher);
    vscf_signer_release_random(self->signer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_setup_defaults(vssq_messenger_file_cipher_t *self) {

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        const vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return vssq_status_RNG_FAILED;
        }
        vssq_messenger_file_cipher_take_random(self, vscf_ctr_drbg_impl(random));
    }

    return vssq_status_SUCCESS;
}

//
//  Return key length for encrypt file.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_init_encryption_out_key_len(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    return 128;
}

//
//  Encryption initialization.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_init_encryption(vssq_messenger_file_cipher_t *self, vsc_buffer_t *out_key) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_buffer_is_valid(out_key));
    VSSQ_ASSERT(vsc_buffer_unused_len(out_key) >= vssq_messenger_file_cipher_init_encryption_out_key_len(self));


    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssq_error_t error;
    vssq_error_reset(&error);

    vscf_impl_t *file_private_key = NULL;
    vscf_impl_t *file_public_key = NULL;

    //
    //  Reset signer.
    //
    vscf_signer_reset(self->signer);

    //
    //  Reset cipher.
    //
    vscf_recipient_cipher_clear_recipients(self->recipient_cipher);
    vscf_recipient_cipher_clear_signers(self->recipient_cipher);

    file_private_key =
            vscf_key_provider_generate_private_key(self->key_provider, vscf_alg_id_ED25519, &foundation_error);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_GENERATE_PRIVATE_KEY_FAILED;
        goto cleanup;
    }

    foundation_error.status = vscf_key_provider_export_private_key(self->key_provider, file_private_key, out_key);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_EXPORT_PRIVATE_KEY_FAILED;
        goto cleanup;
    }

    file_public_key = vscf_private_key_extract_public_key(file_private_key);
    vscf_recipient_cipher_add_key_recipient(
            self->recipient_cipher, vsc_str_as_data(cipher_recipient_id), file_public_key);

    foundation_error.status = vscf_recipient_cipher_start_encryption(self->recipient_cipher);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

cleanup:
    vscf_impl_destroy(&file_private_key);
    vscf_impl_destroy(&file_public_key);

    return vssq_error_status(&error);
}

//
//  Return encryption header length.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_start_encryption_out_len(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vscf_recipient_cipher_message_info_len(self->recipient_cipher);
}

//
//  Start encryption and return header.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_start_encryption(vssq_messenger_file_cipher_t *self, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_file_cipher_start_encryption_out_len(self));

    vscf_recipient_cipher_pack_message_info(self->recipient_cipher, out);

    return vssq_status_SUCCESS;
}

//
//  Return encryption process output buffer length.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_process_encryption_out_len(vssq_messenger_file_cipher_t *self, size_t data_len) {

    VSSQ_ASSERT_PTR(self);

    return vscf_recipient_cipher_encryption_out_len(self->recipient_cipher, data_len);
}

//
//  Encrypt data and return encrypted buffer.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_process_encryption(vssq_messenger_file_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_data_is_valid(data));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_file_cipher_process_encryption_out_len(self, data.len));

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssq_error_t error;
    vssq_error_reset(&error);

    foundation_error.status = vscf_recipient_cipher_process_encryption(self->recipient_cipher, data, out);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

    vscf_signer_append_data(self->signer, data);

cleanup:
    return error.status;
}

//
//  Return finish encryption data length.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_finish_encryption_out_len(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_file_cipher_process_encryption_out_len(self, 0);
}

//
//  Return finish encryption data length.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_finish_encryption_signature_len(
        vssq_messenger_file_cipher_t *self, const vscf_impl_t *signer_private_key) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(signer_private_key);

    return vscf_signer_signature_len(self->signer, signer_private_key);
}

//
//  Finish encryption and return last part of data.
//  Also signature is returned.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_finish_encryption(vssq_messenger_file_cipher_t *self, const vscf_impl_t *signer_private_key,
        vsc_buffer_t *out, vsc_buffer_t *signature) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(signer_private_key);
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_file_cipher_finish_encryption_out_len(self));
    VSSQ_ASSERT(vsc_buffer_is_valid(signature));
    VSSQ_ASSERT(vsc_buffer_unused_len(signature) >=
                vssq_messenger_file_cipher_finish_encryption_signature_len(self, signer_private_key));

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Write the last chunk.
    //
    foundation_error.status = vscf_recipient_cipher_finish_encryption(self->recipient_cipher, out);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

    //
    //  Produce signature.
    //
    foundation_error.status = vscf_signer_sign(self->signer, signer_private_key, signature);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

cleanup:
    return error.status;
}

//
//  Start decryption with a key generated during encryption and signature.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_start_decryption(vssq_messenger_file_cipher_t *self, vsc_data_t key, vsc_data_t signature) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_data_is_valid(key));

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssq_error_t error;
    vssq_error_reset(&error);

    vscf_impl_t *private_key = NULL;

    //
    //  Reset verifier.
    //
    foundation_error.status = vscf_verifier_reset(self->verifier, signature);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED;
        goto cleanup;
    }

    //
    //  Reset cipher.
    //
    vscf_recipient_cipher_clear_recipients(self->recipient_cipher);
    vscf_recipient_cipher_clear_signers(self->recipient_cipher);

    private_key = vscf_key_provider_import_private_key(self->key_provider, key, &foundation_error);

    foundation_error.status = vscf_recipient_cipher_start_decryption_with_key(
            self->recipient_cipher, vsc_str_as_data(cipher_recipient_id), private_key, vsc_data_empty());
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED;
        goto cleanup;
    }

cleanup:
    vscf_impl_destroy(&private_key);

    return error.status;
}

//
//  Return decryption data length.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_process_decryption_out_len(vssq_messenger_file_cipher_t *self, size_t data_len) {

    VSSQ_ASSERT_PTR(self);
    return vscf_recipient_cipher_decryption_out_len(self->recipient_cipher, data_len);
}

//
//  Decryption process.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_process_decryption(vssq_messenger_file_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_data_is_valid(data));
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(!vsc_buffer_is_reverse(out));

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Decrypt current chunk.
    //
    byte *out_begin = vsc_buffer_unused_bytes(out);

    foundation_error.status = vscf_recipient_cipher_process_decryption(self->recipient_cipher, data, out);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED;
        goto cleanup;
    }

    byte *out_end = vsc_buffer_unused_bytes(out);

    //
    //  Append decrypted chunk to the verifier.
    //
    vsc_data_t decryptd_data = vsc_data(out_begin, (size_t)(out_end - out_begin));

    vscf_verifier_append_data(self->verifier, decryptd_data);

cleanup:
    return error.status;
}

//
//  Return finish data part length.
//
VSSQ_PUBLIC size_t
vssq_messenger_file_cipher_finish_decryption_out_len(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vscf_recipient_cipher_decryption_out_len(self->recipient_cipher, 0);
}

//
//  Finish decryption and check signature.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_finish_decryption(
        vssq_messenger_file_cipher_t *self, const vscf_impl_t *signer_public_key, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(signer_public_key);
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_file_cipher_finish_decryption_out_len(self));
    VSSQ_ASSERT(!vsc_buffer_is_reverse(out));

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vsc_buffer_t *public_key_id = NULL;

    //
    //  Accomplish decryption.
    //
    byte *out_begin = vsc_buffer_unused_bytes(out);

    foundation_error.status = vscf_recipient_cipher_finish_decryption(self->recipient_cipher, out);
    if (vscf_error_has_error(&foundation_error)) {
        error.status = vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED;
        goto cleanup;
    }

    byte *out_end = vsc_buffer_unused_bytes(out);

    //
    //  Check signature.
    //
    vsc_data_t decryptd_data = vsc_data(out_begin, (size_t)(out_end - out_begin));
    vscf_verifier_append_data(self->verifier, decryptd_data);

    const bool verified = vscf_verifier_verify(self->verifier, signer_public_key);
    if (!verified) {
        error.status = vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED;
        goto cleanup;
    }

cleanup:
    vsc_buffer_destroy(&public_key_id);

    return error.status;
}
