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
//  Wraps any symmetric cipher algorithm to add padding to plaintext
//  to prevent message guessing attacks based on a ciphertext length.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_padding_cipher.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_cipher.h"
#include "vscf_padding.h"
#include "vscf_padding_cipher_defs.h"

#include <pb_decode.h>
#include <pb_encode.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_padding_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_padding_cipher_init_ctx(vscf_padding_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_padding_cipher_cleanup_ctx(vscf_padding_cipher_t *self);

//
//  Reset buffer. Ensures capacity is enough.
//
static void
vscf_padding_cipher_reset_buffer(vsc_buffer_t *buffer, size_t capacity);

static vscf_status_t
vscf_padding_cipher_finish_encryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

static vscf_status_t
vscf_padding_cipher_finish_decryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return size of 'vscf_padding_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_ctx_size(void) {

    return sizeof(vscf_padding_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_padding_cipher_init(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_padding_cipher_t));

    self->refcnt = 1;

    vscf_padding_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_padding_cipher_cleanup(vscf_padding_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_padding_cipher_cleanup_ctx(self);

    vscf_padding_cipher_release_cipher(self);
    vscf_padding_cipher_release_padding(self);

    vscf_zeroize(self, sizeof(vscf_padding_cipher_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_padding_cipher_t *
vscf_padding_cipher_new(void) {

    vscf_padding_cipher_t *self = (vscf_padding_cipher_t *) vscf_alloc(sizeof (vscf_padding_cipher_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_padding_cipher_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_padding_cipher_delete(vscf_padding_cipher_t *self) {

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

    vscf_padding_cipher_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_padding_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_padding_cipher_destroy(vscf_padding_cipher_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_padding_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vscf_padding_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_padding_cipher_t *
vscf_padding_cipher_shallow_copy(vscf_padding_cipher_t *self) {

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
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_padding_cipher_use_cipher(vscf_padding_cipher_t *self, vscf_impl_t *cipher) {

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
vscf_padding_cipher_take_cipher(vscf_padding_cipher_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = cipher;
}

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_padding_cipher_release_cipher(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->cipher);
}

//
//  Setup dependency to the interface 'padding' with shared ownership.
//
VSCF_PUBLIC void
vscf_padding_cipher_use_padding(vscf_padding_cipher_t *self, vscf_impl_t *padding) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding);
    VSCF_ASSERT(self->padding == NULL);

    VSCF_ASSERT(vscf_padding_is_implemented(padding));

    self->padding = vscf_impl_shallow_copy(padding);
}

//
//  Setup dependency to the interface 'padding' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_padding_cipher_take_padding(vscf_padding_cipher_t *self, vscf_impl_t *padding) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding);
    VSCF_ASSERT(self->padding == NULL);

    VSCF_ASSERT(vscf_padding_is_implemented(padding));

    self->padding = padding;
}

//
//  Release dependency to the interface 'padding'.
//
VSCF_PUBLIC void
vscf_padding_cipher_release_padding(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->padding);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_padding_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_padding_cipher_init_ctx(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    self->padding_buffer = vsc_buffer_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_padding_cipher_cleanup_ctx(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->padding_buffer);
}

//
//  Start sequential encryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_encryption(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);

    vscf_padding_start_data_processing(self->padding);
    vscf_cipher_start_encryption(self->cipher);
}

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_decryption(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);

    vscf_padding_start_padded_data_processing(self->padding);
    vscf_cipher_start_decryption(self->cipher);
}

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_padding_cipher_update(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_out_len(self, data.len));
    VSCF_ASSERT(vscf_cipher_state(self->cipher) != vscf_cipher_state_INITIAL);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        vscf_cipher_update(self->cipher, vscf_padding_process_data(self->padding, data), out);
    } else {
        vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_cipher_decrypted_out_len(self->cipher, data.len));
        vscf_cipher_update(self->cipher, data, self->padding_buffer);
        vscf_padding_process_padded_data(self->padding, vsc_buffer_data(self->padding_buffer), out);
    }
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an current mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_out_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT(vscf_cipher_state(self->cipher) != vscf_cipher_state_INITIAL);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        return vscf_padding_cipher_encrypted_out_len(self, data_len);
    } else {
        return vscf_padding_cipher_decrypted_out_len(self, data_len);
    }
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an encryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_encrypted_out_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    if (data_len > 0) {
        const size_t len = vscf_cipher_encrypted_out_len(self->cipher, data_len);
        return len;
    }

    const size_t padding_len = vscf_padding_len(self->padding);
    const size_t len =
            vscf_cipher_encrypted_out_len(self->cipher, padding_len) + vscf_cipher_encrypted_out_len(self->cipher, 0);
    return len;
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an decryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_decrypted_out_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    const size_t len = vscf_cipher_decrypted_out_len(self->cipher, data_len);
    return len;
}

//
//  Accomplish encryption or decryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_finish(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        return vscf_padding_cipher_finish_encryption(self, out);
    } else {
        return vscf_padding_cipher_finish_decryption(self, out);
    }
}

//
//  Reset buffer. Ensures capacity is enough.
//
static void
vscf_padding_cipher_reset_buffer(vsc_buffer_t *buffer, size_t capacity) {

    VSCF_ASSERT_PTR(buffer);

    if (vsc_buffer_is_valid(buffer) && vsc_buffer_capacity(buffer) >= capacity) {
        vsc_buffer_erase(buffer);
    } else if (capacity > 0) {
        vsc_buffer_release(buffer);
        vsc_buffer_alloc(buffer, capacity);
    } else {
        vsc_buffer_release(buffer);
    }
}

static vscf_status_t
vscf_padding_cipher_finish_encryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_encrypted_out_len(self, 0));

    //
    //  Create padding.
    //
    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_padding_len(self->padding));
    const vscf_status_t padding_status = vscf_padding_finish_data_processing(self->padding, self->padding_buffer);

    if (padding_status != vscf_status_SUCCESS) {
        return padding_status;
    }

    //
    //  Encrypt padding.
    //
    vscf_cipher_update(self->cipher, vsc_buffer_data(self->padding_buffer), out);
    vsc_buffer_erase(self->padding_buffer);

    //
    //  Finish encryption.
    //
    const vscf_status_t enc_status = vscf_cipher_finish(self->cipher, out);

    return enc_status;
}

static vscf_status_t
vscf_padding_cipher_finish_decryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_decrypted_out_len(self, 0));

    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_cipher_decrypted_out_len(self->cipher, 0));

    const vscf_status_t status = vscf_cipher_finish(self->cipher, self->padding_buffer);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    vscf_padding_process_padded_data(self->padding, vsc_buffer_data(self->padding_buffer), out);
    vsc_buffer_erase(self->padding_buffer);

    const vscf_status_t trim_status = vscf_padding_finish_padded_data_processing(self->padding, out);
    if (trim_status != vscf_status_SUCCESS) {
        return status;
    }

    return vscf_status_SUCCESS;
}
