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

#ifndef VSCF_CHUNK_CIPHER_H_INCLUDED
#define VSCF_CHUNK_CIPHER_H_INCLUDED

// clang-format on
//  @end

//  @generated_header_includes
// --------------------------------------------------------------------------
// clang-format off
//  Generated header includes start.
// --------------------------------------------------------------------------

#include "vscf_library.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_status.h"

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
extern "C" {
#endif

//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'chunk cipher' context.
//
typedef struct vscf_chunk_cipher_t vscf_chunk_cipher_t;

//
//  Return size of 'vscf_chunk_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_chunk_cipher_init(vscf_chunk_cipher_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_chunk_cipher_cleanup(vscf_chunk_cipher_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_chunk_cipher_t *
vscf_chunk_cipher_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_chunk_cipher_delete(vscf_chunk_cipher_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_chunk_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_chunk_cipher_destroy(vscf_chunk_cipher_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_chunk_cipher_t *
vscf_chunk_cipher_shallow_copy(vscf_chunk_cipher_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_chunk_cipher_use_random(vscf_chunk_cipher_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_chunk_cipher_take_random(vscf_chunk_cipher_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_chunk_cipher_release_random(vscf_chunk_cipher_t *self);

//
//  Set the 32-byte AES-256 encryption key.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_key(vscf_chunk_cipher_t *self, vsc_data_t key);

//
//  Set the 12-byte initial nonce for decryption.
//  Not needed for encryption: nonce is generated automatically in start_encryption.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_nonce(vscf_chunk_cipher_t *self, vsc_data_t nonce);

//
//  Set the plaintext chunk size in bytes. Default is 65536.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_chunk_size(vscf_chunk_cipher_t *self, size_t chunk_size);

//
//  Return the 12-byte initial nonce.
//  Valid after calling start_encryption; store in CMS custom params for decryption.
//
VSCF_PUBLIC vsc_data_t
vscf_chunk_cipher_nonce(const vscf_chunk_cipher_t *self);

//
//  Return nonce length in bytes (always 12).
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_nonce_len(const vscf_chunk_cipher_t *self);

//
//  Return buffer length required to hold output of process_encryption and finish_encryption.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_encryption_out_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Initiate encryption. Generates a random 12-byte initial nonce.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_start_encryption(vscf_chunk_cipher_t *self) VSCF_NODISCARD;

//
//  Process encryption of a new portion of data.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_process_encryption(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Encrypt any remaining pending data and finalize the stream.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_finish_encryption(vscf_chunk_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return buffer length required to hold output of process_decryption and finish_decryption.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_decryption_out_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Initiate decryption. Caller must call set_nonce with the initial nonce from CMS before this.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_start_decryption(vscf_chunk_cipher_t *self) VSCF_NODISCARD;

//
//  Process decryption of a new portion of data.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_process_decryption(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Decrypt any remaining pending data and finalize the stream.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_finish_decryption(vscf_chunk_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return the number of frames the sequential encryption path emits for a plaintext of the
//  given length: floor(data_len / chunk_size) + 1. The trailing frame (the one with is_last=true)
//  is empty when data_len is an exact multiple of chunk_size. Use this to drive random-access /
//  parallel encryption via encrypt_at over indices 0 .. chunk_count-1, placing is_last on the
//  highest index. Requires chunk_size to be set (> 0).
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_chunk_count(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Encrypt a single chunk at an explicit index for random-access / parallel encryption, writing
//  the frame counter_le64[8] | ciphertext | tag[16]. Independent of the start/process/finish
//  state machine; requires key, initial nonce, and chunk_size to be set, and the instance to be
//  in the INITIAL state (call before, or instead of, start_encryption).
//
//  WARNING (nonce safety): each chunk_index must be encrypted at most ONCE per (key, initial_nonce);
//  AES-GCM nonce reuse is catastrophic. This API is per-call and does NOT track or enforce
//  uniqueness — the caller owns it. Thread-safe: each call uses a per-call local cipher context and
//  only reads the instance's key/nonce/chunk_size, so a single configured instance may be used
//  concurrently from multiple threads for parallel encryption (no shared mutable cipher state, no
//  lock). Whole-file only: the caller must know the total chunk count (see chunk_count) to place
//  exactly one is_last frame.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_encrypt_at(vscf_chunk_cipher_t *self, uint64_t chunk_index, bool is_last, vsc_data_t plaintext, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Authenticate and decrypt a single frame as an explicit chunk index for random-access reads.
//  The frame's embedded counter is validated against the passed-in chunk_index (a mismatch returns
//  ERROR_BAD_ENCRYPTED_DATA), so callers must pass the true positional index and never trust the
//  frame's own counter. Independent of the streaming state machine; requires key, initial nonce,
//  and chunk_size to be set, and the instance to be in the INITIAL state.
//
//  Thread-safe: uses a per-call local cipher context and only reads the instance's
//  key/nonce/chunk_size, so a single configured instance may be used concurrently from multiple
//  threads for parallel/random-access decryption (no shared mutable cipher state, no lock). Note:
//  this authenticates which frame is last (is_last) and each frame's position, but not the total
//  number of frames — protect against truncation by authenticating the chunk count out of band
//  (or deriving it from the ciphertext length).
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_decrypt_at(vscf_chunk_cipher_t *self, uint64_t chunk_index, bool is_last, vsc_data_t frame, vsc_buffer_t *out) VSCF_NODISCARD;

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end

#ifdef __cplusplus
}
#endif

//  @footer
#endif // VSCF_CHUNK_CIPHER_H_INCLUDED
//  @end
