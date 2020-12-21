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

#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
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

    self->key_provider = vscf_key_provider_new();
    self->recipient_cipher = vscf_recipient_cipher_new();
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
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_file_cipher_did_setup_random(vssq_messenger_file_cipher_t *self) {

    VSSQ_ASSERT_PTR(self);
    vssq_messenger_file_cipher_release_random(self);
    vssq_messenger_file_cipher_use_random(self, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_file_cipher_did_release_random(vssq_messenger_file_cipher_t *self) {

    vssq_messenger_file_cipher_release_random(self);
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

VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_init_encryption(vssq_messenger_file_cipher_t *self, vsc_buffer_t *key) {

    vscf_impl_t *private_key = NULL;
    vscf_impl_t *public_key = NULL;

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);
    vssq_error_t status;
    vssq_error_reset(&status);

    private_key = vscf_key_provider_generate_private_key(self->key_provider,
                                                                vscf_alg_id_ED25519, &foundation_error);
    if (vscf_error_has_error(&foundation_error)) {
        status.status = vssq_status_GENERATE_PRIVATE_KEY_FAILED;
        goto cleanup;
    }

    foundation_error.status = vscf_key_provider_export_private_key(self->key_provider, private_key,
                                                                   key);
    if (foundation_error.status != vscf_status_SUCCESS) {
        status.status = vssq_status_EXPORT_PRIVATE_KEY_FAILED;
        goto cleanup;
    }

    public_key = vscf_private_key_extract_public_key(private_key);
    vscf_recipient_cipher_add_key_recipient(self->recipient_cipher, vsc_str_as_data(cipher_recipient_id), public_key);
    foundation_error.status = vscf_recipient_cipher_add_signer(self->recipient_cipher,
                                                               vsc_str_as_data(cipher_recipient_id), private_key);
    if (foundation_error.status != vscf_status_SUCCESS) {
        status.status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    cleanup:
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);

    return vssq_error_status(&status);
}

VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_start_encryption(vssq_messenger_file_cipher_t *self, size_t data_size, vsc_buffer_t *out) {

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);
    vssq_error_t status;
    vssq_error_reset(&status);
    size_t message_info_len = 0;

    message_info_len = vscf_recipient_cipher_message_info_len(self->recipient_cipher);
    foundation_error.status = vscf_recipient_cipher_start_signed_encryption(self->recipient_cipher, data_size);
    if (foundation_error.status != vscf_status_SUCCESS) {
        status.status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }
    out = vsc_buffer_new_with_capacity(message_info_len);
    vscf_recipient_cipher_pack_message_info(self->recipient_cipher, out);

    status.status = vssq_status_SUCCESS;

    cleanup:

    return status.status;
}

VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_process_encryption(vssq_messenger_file_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);
    vssq_error_t status;
    vssq_error_reset(&status);

    foundation_error.status = vscf_recipient_cipher_process_encryption(self->recipient_cipher, data, out);
    if (foundation_error.status != vscf_status_SUCCESS) {
        status.status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    status.status = vssq_status_SUCCESS;

    cleanup:

    return status.status;
}

VSSQ_PUBLIC vssq_status_t
vssq_messenger_file_cipher_finish_encryption(vssq_messenger_file_cipher_t *self, vsc_buffer_t *out) {

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);
    vssq_error_t status;
    vssq_error_reset(&status);
    size_t enc_msg_info_footer_len = 0;

    foundation_error.status = vscf_recipient_cipher_finish_encryption(self->recipient_cipher, out);
    if (vscf_error_has_error(&foundation_error)) {
        status.status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(self->recipient_cipher);
    out = vsc_buffer_new_with_capacity(enc_msg_info_footer_len);
    foundation_error.status = vscf_recipient_cipher_pack_message_info_footer(self->recipient_cipher, out);
    if (foundation_error.status != vscf_status_SUCCESS) {
        //? vsc_buffer_destroy(&out);
        status.status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    status.status = vssq_status_SUCCESS;

    cleanup:

    return status.status;
}
