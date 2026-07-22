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
#include "vscf_alg_id.h"
#include "vscf_cipher_state.h"

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
//  Public integral constants.
//
enum {
    //
    //  Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    //
    vscf_chunk_cipher_NONCE_LEN = 12,
    //
    //  Cipher key length in bytes.
    //
    vscf_chunk_cipher_KEY_LEN = 32,
    //
    //  Cipher key length in bits.
    //
    vscf_chunk_cipher_KEY_BITLEN = 256,
    //
    //  Cipher block length in bytes.
    //
    vscf_chunk_cipher_BLOCK_LEN = 16
};

//
//  Handles implementation details.
//
typedef struct vscf_chunk_cipher_t vscf_chunk_cipher_t;

//
//  Return size of 'vscf_chunk_cipher_t' type.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_chunk_cipher_impl(vscf_chunk_cipher_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_chunk_cipher_impl_const(const vscf_chunk_cipher_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_chunk_cipher_init(vscf_chunk_cipher_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_chunk_cipher_init()'.
//
VSCF_PUBLIC void
vscf_chunk_cipher_cleanup(vscf_chunk_cipher_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_chunk_cipher_t *
vscf_chunk_cipher_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_chunk_cipher_new()'.
//
VSCF_PUBLIC void
vscf_chunk_cipher_delete(vscf_chunk_cipher_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_chunk_cipher_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_chunk_cipher_destroy(vscf_chunk_cipher_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
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
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_chunk_cipher_alg_id(const vscf_chunk_cipher_t *self);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_chunk_cipher_produce_alg_info(const vscf_chunk_cipher_t *self);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_restore_alg_info(vscf_chunk_cipher_t *self, const vscf_impl_t *alg_info) VSCF_NODISCARD;

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_encrypt(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_encrypted_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Precise length calculation of encrypted data.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_precise_encrypted_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_decrypt(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_decrypted_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Setup IV or nonce.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_nonce(vscf_chunk_cipher_t *self, vsc_data_t nonce);

//
//  Set cipher encryption / decryption key.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_key(vscf_chunk_cipher_t *self, vsc_data_t key);

//
//  Return cipher's current state.
//
VSCF_PRIVATE vscf_cipher_state_t
vscf_chunk_cipher_state(const vscf_chunk_cipher_t *self);

//
//  Start sequential encryption.
//
VSCF_PUBLIC void
vscf_chunk_cipher_start_encryption(vscf_chunk_cipher_t *self);

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_chunk_cipher_start_decryption(vscf_chunk_cipher_t *self);

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_chunk_cipher_update(vscf_chunk_cipher_t *self, vsc_data_t data, vsc_buffer_t *out);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an current mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_out_len(vscf_chunk_cipher_t *self, size_t data_len);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an encryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_encrypted_out_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an decryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_decrypted_out_len(const vscf_chunk_cipher_t *self, size_t data_len);

//
//  Accomplish encryption or decryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_chunk_cipher_finish(vscf_chunk_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Set the plaintext chunk size in bytes. Default is 65536.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_chunk_size(vscf_chunk_cipher_t *self, size_t chunk_size);

//
//  Return the 12-byte initial nonce.
//  Valid after calling start_encryption. On the generic CMS path the
//  nonce is carried in the produced 'chunked alg info' (self-describing),
//  so no out-of-band custom params are needed.
//
VSCF_PUBLIC vsc_data_t
vscf_chunk_cipher_nonce(const vscf_chunk_cipher_t *self);

//
//  Return buffer length required to hold output of process_encryption and finish_encryption.
//
VSCF_PUBLIC size_t
vscf_chunk_cipher_encryption_out_len(const vscf_chunk_cipher_t *self, size_t data_len);

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

//
//  Set associated data bound into the stream authentication.
//  The generic encryptor/decryptor (recipient cipher) sets this to the
//  serialized CMS 'data encryption alg info' so metadata tampering
//  (OID swap, chunk_size/initial_nonce change) fails closed. Must be
//  set before start_encryption/start_decryption (and before
//  encrypt_at/decrypt_at). Empty auth_data preserves the shipped raw
//  frame format.
//
VSCF_PUBLIC void
vscf_chunk_cipher_set_auth_data(vscf_chunk_cipher_t *self, vsc_data_t auth_data);

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
