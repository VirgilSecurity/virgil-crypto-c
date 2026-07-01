//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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

#include "vscf_chunk_cipher.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_chunk_cipher_defs.h"
#include "vscf_aes256_gcm.h"
#include "vscf_aes256_gcm_defs.h"
#include "vscf_random.h"
#include "vscf_status.h"
#include "vscf_cipher_state.h"

#include <string.h>
#include <stdint.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_chunk_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_chunk_cipher_init_ctx(vscf_chunk_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_chunk_cipher_cleanup_ctx(vscf_chunk_cipher_t *self);

//
//  Encrypt one plaintext chunk and write frame: counter_le64[8] | ciphertext | tag[16].
//
static vscf_status_t
vscf_chunk_cipher_encrypt_chunk(vscf_chunk_cipher_t *self, vsc_data_t plaintext, uint64_t chunk_index, bool is_last, vsc_buffer_t *out);

//
//  Authenticate and decrypt one ciphertext frame: counter_le64[8] | ciphertext | tag[16].
//  The frame's embedded counter is validated against expected_index.
//
static vscf_status_t
vscf_chunk_cipher_decrypt_chunk(vscf_chunk_cipher_t *self, vsc_data_t frame, uint64_t expected_index, bool is_last, vsc_buffer_t *out);

//
//  Return size of 'vscf_chunk_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_ctx_size(void) {

    return sizeof(vscf_chunk_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_chunk_cipher_init(vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_chunk_cipher_t));

    self->refcnt = 1;

    vscf_chunk_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_chunk_cipher_cleanup(vscf_chunk_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_chunk_cipher_cleanup_ctx(self);

    vscf_chunk_cipher_release_random(self);

    vscf_zeroize(self, sizeof(vscf_chunk_cipher_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_chunk_cipher_t *
vscf_chunk_cipher_new(void) {

    vscf_chunk_cipher_t *self = (vscf_chunk_cipher_t *) vscf_alloc(sizeof (vscf_chunk_cipher_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_chunk_cipher_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_chunk_cipher_delete(vscf_chunk_cipher_t *self) {

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

    vscf_chunk_cipher_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_chunk_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_chunk_cipher_destroy(vscf_chunk_cipher_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_chunk_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vscf_chunk_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_chunk_cipher_t *
vscf_chunk_cipher_shallow_copy(vscf_chunk_cipher_t *self) {

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
vscf_chunk_cipher_use_random(vscf_chunk_cipher_t *self, vscf_impl_t *random) {

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
vscf_chunk_cipher_take_random(vscf_chunk_cipher_t *self, vscf_impl_t *random) {

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
vscf_chunk_cipher_release_random(vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end

#define VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE 65536

//
//  Hard cap on the frame counter: nonce_i is derived from the counter, so the
//  counter must never repeat under the same key and initial nonce.
//  2^48 frames matches STREAM-style constructions (Tink, libsodium secretstream).
//
#define VSCF_CHUNK_CIPHER_MAX_CHUNK_INDEX (UINT64_C(1) << 48)

static void
vscf_chunk_cipher_init_ctx(vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    self->aes256_gcm = vscf_aes256_gcm_new();
    self->chunk_size = VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE;
}

static void
vscf_chunk_cipher_cleanup_ctx(vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_aes256_gcm_destroy(&self->aes256_gcm);
    vsc_buffer_destroy(&self->key);
    vsc_buffer_destroy(&self->nonce_buffer);
    vsc_buffer_destroy(&self->pending);
}

VSCF_PUBLIC void
vscf_chunk_cipher_set_key(vscf_chunk_cipher_t *self, vsc_data_t key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len == vscf_aes256_gcm_KEY_LEN);

    vsc_buffer_destroy(&self->key);
    self->key = vsc_buffer_new_with_data(key);
    vsc_buffer_make_secure(self->key);
}

VSCF_PUBLIC void
vscf_chunk_cipher_set_nonce(vscf_chunk_cipher_t *self, vsc_data_t nonce) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(nonce));
    VSCF_ASSERT(nonce.len == vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_destroy(&self->nonce_buffer);
    self->nonce_buffer = vsc_buffer_new_with_data(nonce);
    vsc_buffer_make_secure(self->nonce_buffer);
}

VSCF_PUBLIC void
vscf_chunk_cipher_set_chunk_size(vscf_chunk_cipher_t *self, size_t chunk_size) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(chunk_size > 0);
    VSCF_ASSERT(self->state == vscf_cipher_state_INITIAL);

    self->chunk_size = chunk_size;
}

VSCF_PUBLIC vsc_data_t
vscf_chunk_cipher_nonce(const vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->nonce_buffer);

    return vsc_buffer_data(self->nonce_buffer);
}

VSCF_PUBLIC size_t
vscf_chunk_cipher_nonce_len(const vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_aes256_gcm_NONCE_LEN;
}

VSCF_PUBLIC size_t
vscf_chunk_cipher_encryption_out_len(const vscf_chunk_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    const size_t chunk_size = self->chunk_size > 0 ? self->chunk_size : VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE;
    // frame_alloc_size includes the BLOCK_LEN headroom required by vscf_aes256_gcm_encrypted_len's ASSERT
    const size_t frame_alloc_size = chunk_size + 8 + vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN;
    // +1 covers the trailing partial chunk emitted by finish_encryption
    const size_t num_frames = (data_len / chunk_size) + 1;
    VSCF_ASSERT(num_frames <= SIZE_MAX / frame_alloc_size);
    return num_frames * frame_alloc_size;
}

VSCF_PUBLIC size_t
vscf_chunk_cipher_decryption_out_len(const vscf_chunk_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    const size_t chunk_size = self->chunk_size > 0 ? self->chunk_size : VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE;
    const size_t full_frame_size = chunk_size + 8 + vscf_aes256_gcm_AUTH_TAG_LEN;
    // +1 for any pending partial frame carried across calls
    const size_t num_frames = (data_len / full_frame_size) + 1;
    const size_t plaintext_per_frame = chunk_size + vscf_aes256_gcm_BLOCK_LEN;
    VSCF_ASSERT(num_frames <= SIZE_MAX / plaintext_per_frame);
    return num_frames * plaintext_per_frame;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_start_encryption(vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->key);

    if (self->chunk_size == 0) {
        self->chunk_size = VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE;
    }

    vsc_buffer_destroy(&self->nonce_buffer);
    self->nonce_buffer = vsc_buffer_new_with_capacity(vscf_aes256_gcm_NONCE_LEN);
    vsc_buffer_make_secure(self->nonce_buffer);

    vscf_status_t status = vscf_random(self->random, vscf_aes256_gcm_NONCE_LEN, self->nonce_buffer);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    vsc_buffer_destroy(&self->pending);
    self->pending = vsc_buffer_new_with_capacity(self->chunk_size);

    self->chunk_index = 0;
    self->state = vscf_cipher_state_ENCRYPTION;

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_process_encryption(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(self->state == vscf_cipher_state_ENCRYPTION);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chunk_cipher_encryption_out_len(self, data.len));

    const byte *src = data.bytes;
    size_t src_len = data.len;

    while (src_len > 0) {
        const size_t pending_len = vsc_buffer_len(self->pending);
        const size_t fill = self->chunk_size - pending_len;

        if (src_len < fill) {
            vsc_buffer_write_data(self->pending, vsc_data(src, src_len));
            src_len = 0;
        } else {
            vsc_buffer_write_data(self->pending, vsc_data(src, fill));
            src += fill;
            src_len -= fill;

            const vscf_status_t status = vscf_chunk_cipher_encrypt_chunk(
                    self, vsc_buffer_data(self->pending), self->chunk_index, false, out);
            if (status != vscf_status_SUCCESS) {
                return status;
            }
            self->chunk_index++;
            vsc_buffer_reset(self->pending);
        }
    }

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_finish_encryption(vscf_chunk_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(self->state == vscf_cipher_state_ENCRYPTION);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chunk_cipher_encryption_out_len(self, 0));

    // Always emit a FIN frame; carries remaining plaintext (if any) or is empty for exact-multiple inputs.
    const vsc_data_t fin_plaintext =
            vsc_buffer_len(self->pending) > 0 ? vsc_buffer_data(self->pending) : vsc_data_empty();
    const vscf_status_t status = vscf_chunk_cipher_encrypt_chunk(self, fin_plaintext, self->chunk_index, true, out);
    vsc_buffer_reset(self->pending);

    self->state = vscf_cipher_state_INITIAL;
    return status;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_start_decryption(vscf_chunk_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key);
    VSCF_ASSERT_PTR(self->nonce_buffer);
    VSCF_ASSERT(vsc_buffer_len(self->nonce_buffer) == vscf_aes256_gcm_NONCE_LEN);

    if (self->chunk_size == 0) {
        self->chunk_size = VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE;
    }

    vsc_buffer_destroy(&self->pending);
    self->pending = vsc_buffer_new_with_capacity(self->chunk_size + 8 + vscf_aes256_gcm_AUTH_TAG_LEN);

    self->chunk_index = 0;
    self->state = vscf_cipher_state_DECRYPTION;

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_process_decryption(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(self->state == vscf_cipher_state_DECRYPTION);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chunk_cipher_decryption_out_len(self, data.len));

    const size_t full_frame_size = self->chunk_size + 8 + vscf_aes256_gcm_AUTH_TAG_LEN;
    const byte *src = data.bytes;
    size_t src_len = data.len;

    while (src_len > 0) {
        const size_t pending_len = vsc_buffer_len(self->pending);
        const size_t fill = full_frame_size - pending_len;

        if (src_len < fill) {
            vsc_buffer_write_data(self->pending, vsc_data(src, src_len));
            src_len = 0;
        } else {
            vsc_buffer_write_data(self->pending, vsc_data(src, fill));
            src += fill;
            src_len -= fill;

            const vscf_status_t status = vscf_chunk_cipher_decrypt_chunk(
                    self, vsc_buffer_data(self->pending), self->chunk_index, false, out);
            if (status != vscf_status_SUCCESS) {
                vsc_buffer_reset(self->pending);
                self->state = vscf_cipher_state_INITIAL;
                return status;
            }
            self->chunk_index++;
            vsc_buffer_reset(self->pending);
        }
    }

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_finish_decryption(vscf_chunk_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(self->state == vscf_cipher_state_DECRYPTION);

    const size_t pending_len = vsc_buffer_len(self->pending);

    // The FIN frame must always be present: minimum is 8 (counter) + 16 (tag) = 24 bytes.
    // A missing or too-short FIN indicates a truncated or corrupted stream.
    if (pending_len < 8 + vscf_aes256_gcm_AUTH_TAG_LEN) {
        self->state = vscf_cipher_state_INITIAL;
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    const vscf_status_t status =
            vscf_chunk_cipher_decrypt_chunk(self, vsc_buffer_data(self->pending), self->chunk_index, true, out);
    vsc_buffer_reset(self->pending);

    self->state = vscf_cipher_state_INITIAL;
    return status;
}

//
//  Core per-chunk crypto, parameterized by the AES-GCM instance. Sequential callers pass the shared
//  self->aes256_gcm (single-threaded per cipher instance); the seek/parallel methods pass a per-call
//  local instance so concurrent calls on one cipher never touch shared mutable cipher state. Reads of
//  self->key / self->nonce_buffer / self->chunk_size are the only shared access and are read-only here.
//
static vscf_status_t
vscf_chunk_cipher_encrypt_chunk_with(vscf_chunk_cipher_t *self, vscf_aes256_gcm_t *gcm, vsc_data_t plaintext,
        uint64_t chunk_index, bool is_last, vsc_buffer_t *out);

static vscf_status_t
vscf_chunk_cipher_decrypt_chunk_with(vscf_chunk_cipher_t *self, vscf_aes256_gcm_t *gcm, vsc_data_t frame,
        uint64_t expected_index, bool is_last, vsc_buffer_t *out);

VSCF_PUBLIC size_t
vscf_chunk_cipher_chunk_count(const vscf_chunk_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    // Matches the sequential path: full chunks plus one always-emitted trailing frame
    // (empty when data_len is an exact multiple of chunk_size).
    const size_t chunk_size = self->chunk_size > 0 ? self->chunk_size : VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE;
    return (data_len / chunk_size) + 1;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_encrypt_at(
        vscf_chunk_cipher_t *self, uint64_t chunk_index, bool is_last, vsc_data_t plaintext, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(plaintext));
    VSCF_ASSERT_PTR(out);

    // Seek/parallel methods run outside the start/process/finish state machine. The delegated helper
    // asserts (aborts) on missing key/nonce, so every precondition is soft-checked here first.
    if (self->state != vscf_cipher_state_INITIAL) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }
    if (NULL == self->key || NULL == self->nonce_buffer ||
            vsc_buffer_len(self->nonce_buffer) != vscf_aes256_gcm_NONCE_LEN || self->chunk_size == 0) {
        return vscf_status_ERROR_UNINITIALIZED;
    }

    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chunk_cipher_encryption_out_len(self, plaintext.len));

    // Thread-safe by construction: use a per-call, stack-allocated AES-GCM context, never the shared
    // self->aes256_gcm, so concurrent calls on one instance don't race. self->key/nonce/chunk_size
    // are only read here. No lock and no heap allocation of the context.
    vscf_aes256_gcm_t gcm;
    vscf_aes256_gcm_init(&gcm);
    const vscf_status_t status = vscf_chunk_cipher_encrypt_chunk_with(self, &gcm, plaintext, chunk_index, is_last, out);
    vscf_aes256_gcm_cleanup(&gcm);
    return status;
}

VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_decrypt_at(
        vscf_chunk_cipher_t *self, uint64_t chunk_index, bool is_last, vsc_data_t frame, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(frame));
    VSCF_ASSERT_PTR(out);

    if (self->state != vscf_cipher_state_INITIAL) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }
    if (NULL == self->key || NULL == self->nonce_buffer ||
            vsc_buffer_len(self->nonce_buffer) != vscf_aes256_gcm_NONCE_LEN || self->chunk_size == 0) {
        return vscf_status_ERROR_UNINITIALIZED;
    }

    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chunk_cipher_decryption_out_len(self, frame.len));

    // Thread-safe by construction: per-call, stack-allocated AES-GCM context (see encrypt_at).
    // expected_index is the caller's positional index; the frame's own counter is validated against it.
    vscf_aes256_gcm_t gcm;
    vscf_aes256_gcm_init(&gcm);
    const vscf_status_t status = vscf_chunk_cipher_decrypt_chunk_with(self, &gcm, frame, chunk_index, is_last, out);
    vscf_aes256_gcm_cleanup(&gcm);
    return status;
}

static vscf_status_t
vscf_chunk_cipher_encrypt_chunk(
        vscf_chunk_cipher_t *self, vsc_data_t plaintext, uint64_t chunk_index, bool is_last, vsc_buffer_t *out) {

    // Sequential path: reuse the shared per-instance context (single-threaded per cipher instance).
    return vscf_chunk_cipher_encrypt_chunk_with(self, self->aes256_gcm, plaintext, chunk_index, is_last, out);
}

static vscf_status_t
vscf_chunk_cipher_encrypt_chunk_with(vscf_chunk_cipher_t *self, vscf_aes256_gcm_t *gcm, vsc_data_t plaintext,
        uint64_t chunk_index, bool is_last, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(gcm);
    VSCF_ASSERT_PTR(self->key);
    VSCF_ASSERT_PTR(self->nonce_buffer);
    VSCF_ASSERT(vsc_data_is_valid(plaintext));
    VSCF_ASSERT_PTR(out);

    // A repeated counter would reuse an AES-GCM nonce under the same key.
    if (chunk_index >= VSCF_CHUNK_CIPHER_MAX_CHUNK_INDEX) {
        return vscf_status_ERROR_CHUNK_COUNTER_LIMIT_REACHED;
    }

    // Encode chunk_index as 8-byte little-endian counter (written to frame and used as AAD base)
    const uint64_t idx64 = chunk_index;
    byte counter_bytes[8];
    for (int i = 0; i < 8; i++) {
        counter_bytes[i] = (byte)((idx64 >> (8 * i)) & 0xFF);
    }

    // Build variable-length AAD: counter[8] [|| chunk_size[8] if frame 0] [|| FIN_MARKER[8] if last]
    byte aad[24];
    size_t aad_len = 8;
    memcpy(aad, counter_bytes, 8);
    if (idx64 == 0) {
        const uint64_t cs64 = (uint64_t)self->chunk_size;
        for (int i = 0; i < 8; i++) {
            aad[aad_len + i] = (byte)((cs64 >> (8 * i)) & 0xFF);
        }
        aad_len += 8;
    }
    if (is_last) {
        memset(aad + aad_len, 0xFF, 8);
        aad_len += 8;
    }

    // Derive per-chunk nonce: initial_nonce XOR (0x00000000 || uint64_be(chunk_index))
    byte nonce_i[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_i, vsc_buffer_bytes(self->nonce_buffer), vscf_aes256_gcm_NONCE_LEN);
    for (int i = 0; i < 8; i++) {
        nonce_i[4 + i] ^= (byte)((idx64 >> (8 * (7 - i))) & 0xFF);
    }

    vscf_aes256_gcm_set_key(gcm, vsc_buffer_data(self->key));
    vscf_aes256_gcm_set_nonce(gcm, vsc_data(nonce_i, vscf_aes256_gcm_NONCE_LEN));
    vscf_erase(nonce_i, sizeof(nonce_i));

    // Frame: counter_le64[8] | ciphertext[N] | tag[16]
    vsc_buffer_write_data(out, vsc_data(counter_bytes, 8));
    return vscf_aes256_gcm_auth_encrypt(gcm, plaintext, vsc_data(aad, aad_len), out, NULL);
}

static vscf_status_t
vscf_chunk_cipher_decrypt_chunk(
        vscf_chunk_cipher_t *self, vsc_data_t frame, uint64_t expected_index, bool is_last, vsc_buffer_t *out) {

    // Sequential path: reuse the shared per-instance context (single-threaded per cipher instance).
    return vscf_chunk_cipher_decrypt_chunk_with(self, self->aes256_gcm, frame, expected_index, is_last, out);
}

static vscf_status_t
vscf_chunk_cipher_decrypt_chunk_with(vscf_chunk_cipher_t *self, vscf_aes256_gcm_t *gcm, vsc_data_t frame,
        uint64_t expected_index, bool is_last, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(gcm);
    VSCF_ASSERT_PTR(self->key);
    VSCF_ASSERT_PTR(self->nonce_buffer);
    VSCF_ASSERT(vsc_data_is_valid(frame));
    VSCF_ASSERT_PTR(out);

    // Minimum frame: 8 (counter) + 16 (tag); FIN frame may have 0 ciphertext bytes
    if (frame.len < 8 + vscf_aes256_gcm_AUTH_TAG_LEN) {
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    // Extract and validate the 8-byte little-endian counter
    byte counter_bytes[8];
    memcpy(counter_bytes, frame.bytes, 8);

    uint64_t frame_index64 = 0;
    for (int i = 0; i < 8; i++) {
        frame_index64 |= ((uint64_t)counter_bytes[i]) << (8 * i);
    }

    if (frame_index64 != expected_index) {
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    // A conforming encryptor never produces a frame at or above the counter cap.
    if (frame_index64 >= VSCF_CHUNK_CIPHER_MAX_CHUNK_INDEX) {
        return vscf_status_ERROR_CHUNK_COUNTER_LIMIT_REACHED;
    }

    // Build variable-length AAD matching what encrypt_chunk produced
    byte aad[24];
    size_t aad_len = 8;
    memcpy(aad, counter_bytes, 8);
    if (frame_index64 == 0) {
        const uint64_t cs64 = (uint64_t)self->chunk_size;
        for (int i = 0; i < 8; i++) {
            aad[aad_len + i] = (byte)((cs64 >> (8 * i)) & 0xFF);
        }
        aad_len += 8;
    }
    if (is_last) {
        memset(aad + aad_len, 0xFF, 8);
        aad_len += 8;
    }

    // Derive per-chunk nonce
    byte nonce_i[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_i, vsc_buffer_bytes(self->nonce_buffer), vscf_aes256_gcm_NONCE_LEN);
    for (int i = 0; i < 8; i++) {
        nonce_i[4 + i] ^= (byte)((frame_index64 >> (8 * (7 - i))) & 0xFF);
    }

    vscf_aes256_gcm_set_key(gcm, vsc_buffer_data(self->key));
    vscf_aes256_gcm_set_nonce(gcm, vsc_data(nonce_i, vscf_aes256_gcm_NONCE_LEN));
    vscf_erase(nonce_i, sizeof(nonce_i));

    // Frame: counter[8] | ciphertext[N] | tag[16]
    const size_t ciphertext_len = frame.len - 8 - vscf_aes256_gcm_AUTH_TAG_LEN;
    vsc_data_t ciphertext = vsc_data(frame.bytes + 8, ciphertext_len);
    vsc_data_t tag = vsc_data(frame.bytes + 8 + ciphertext_len, vscf_aes256_gcm_AUTH_TAG_LEN);

    return vscf_aes256_gcm_auth_decrypt(gcm, ciphertext, vsc_data(aad, aad_len), tag, out);
}
