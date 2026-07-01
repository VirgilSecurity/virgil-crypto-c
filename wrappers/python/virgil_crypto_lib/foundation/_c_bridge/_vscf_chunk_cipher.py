# Copyright (C) 2015-2026 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from virgil_crypto_lib._libs import *
from ctypes import *
from ._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_chunk_cipher_t(Structure):
    pass


class VscfChunkCipher(object):
    """Provides stream encryption in fixed-size chunks, where each encrypted
chunk carries its own AES-256-GCM authentication tag.

Nonce derivation follows the TLS 1.3 construction:
    nonce_i = initial_nonce XOR (0x00000000 || uint64_be(i))

Each encrypted frame layout:
    counter_le64[8] | ciphertext[N] | tag[16]

The initial nonce and chunk size must be stored in the CMS message info
custom params by the caller; they are not embedded in the ciphertext stream."""


    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_chunk_cipher_new(self):
        vscf_chunk_cipher_new = self._lib.vscf_chunk_cipher_new
        vscf_chunk_cipher_new.argtypes = []
        vscf_chunk_cipher_new.restype = POINTER(vscf_chunk_cipher_t)
        return vscf_chunk_cipher_new()

    def vscf_chunk_cipher_delete(self, ctx):
        vscf_chunk_cipher_delete = self._lib.vscf_chunk_cipher_delete
        vscf_chunk_cipher_delete.argtypes = [POINTER(vscf_chunk_cipher_t)]
        vscf_chunk_cipher_delete.restype = None
        return vscf_chunk_cipher_delete(ctx)

    def vscf_chunk_cipher_use_random(self, ctx, random):
        vscf_chunk_cipher_use_random = self._lib.vscf_chunk_cipher_use_random
        vscf_chunk_cipher_use_random.argtypes = [POINTER(vscf_chunk_cipher_t), POINTER(vscf_impl_t)]
        vscf_chunk_cipher_use_random.restype = None
        return vscf_chunk_cipher_use_random(ctx, random)

    def vscf_chunk_cipher_set_key(self, ctx, key):
        """Set the 32-byte AES-256 encryption key."""
        vscf_chunk_cipher_set_key = self._lib.vscf_chunk_cipher_set_key
        vscf_chunk_cipher_set_key.argtypes = [POINTER(vscf_chunk_cipher_t), vsc_data_t]
        vscf_chunk_cipher_set_key.restype = None
        return vscf_chunk_cipher_set_key(ctx, key)

    def vscf_chunk_cipher_set_nonce(self, ctx, nonce):
        """Set the 12-byte initial nonce for decryption.
Not needed for encryption: nonce is generated automatically in start_encryption."""
        vscf_chunk_cipher_set_nonce = self._lib.vscf_chunk_cipher_set_nonce
        vscf_chunk_cipher_set_nonce.argtypes = [POINTER(vscf_chunk_cipher_t), vsc_data_t]
        vscf_chunk_cipher_set_nonce.restype = None
        return vscf_chunk_cipher_set_nonce(ctx, nonce)

    def vscf_chunk_cipher_set_chunk_size(self, ctx, chunk_size):
        """Set the plaintext chunk size in bytes. Default is 65536."""
        vscf_chunk_cipher_set_chunk_size = self._lib.vscf_chunk_cipher_set_chunk_size
        vscf_chunk_cipher_set_chunk_size.argtypes = [POINTER(vscf_chunk_cipher_t), c_size_t]
        vscf_chunk_cipher_set_chunk_size.restype = None
        return vscf_chunk_cipher_set_chunk_size(ctx, chunk_size)

    def vscf_chunk_cipher_nonce(self, ctx):
        """Return the 12-byte initial nonce.
Valid after calling start_encryption; store in CMS custom params for decryption."""
        vscf_chunk_cipher_nonce = self._lib.vscf_chunk_cipher_nonce
        vscf_chunk_cipher_nonce.argtypes = [POINTER(vscf_chunk_cipher_t)]
        vscf_chunk_cipher_nonce.restype = vsc_data_t
        return vscf_chunk_cipher_nonce(ctx)

    def vscf_chunk_cipher_nonce_len(self, ctx):
        """Return nonce length in bytes (always 12)."""
        vscf_chunk_cipher_nonce_len = self._lib.vscf_chunk_cipher_nonce_len
        vscf_chunk_cipher_nonce_len.argtypes = [POINTER(vscf_chunk_cipher_t)]
        vscf_chunk_cipher_nonce_len.restype = c_size_t
        return vscf_chunk_cipher_nonce_len(ctx)

    def vscf_chunk_cipher_encryption_out_len(self, ctx, data_len):
        """Return buffer length required to hold output of process_encryption and finish_encryption."""
        vscf_chunk_cipher_encryption_out_len = self._lib.vscf_chunk_cipher_encryption_out_len
        vscf_chunk_cipher_encryption_out_len.argtypes = [POINTER(vscf_chunk_cipher_t), c_size_t]
        vscf_chunk_cipher_encryption_out_len.restype = c_size_t
        return vscf_chunk_cipher_encryption_out_len(ctx, data_len)

    def vscf_chunk_cipher_start_encryption(self, ctx):
        """Initiate encryption. Generates a random 12-byte initial nonce."""
        vscf_chunk_cipher_start_encryption = self._lib.vscf_chunk_cipher_start_encryption
        vscf_chunk_cipher_start_encryption.argtypes = [POINTER(vscf_chunk_cipher_t)]
        vscf_chunk_cipher_start_encryption.restype = c_int
        return vscf_chunk_cipher_start_encryption(ctx)

    def vscf_chunk_cipher_process_encryption(self, ctx, data, out):
        """Process encryption of a new portion of data."""
        vscf_chunk_cipher_process_encryption = self._lib.vscf_chunk_cipher_process_encryption
        vscf_chunk_cipher_process_encryption.argtypes = [POINTER(vscf_chunk_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_chunk_cipher_process_encryption.restype = c_int
        return vscf_chunk_cipher_process_encryption(ctx, data, out)

    def vscf_chunk_cipher_finish_encryption(self, ctx, out):
        """Encrypt any remaining pending data and finalize the stream."""
        vscf_chunk_cipher_finish_encryption = self._lib.vscf_chunk_cipher_finish_encryption
        vscf_chunk_cipher_finish_encryption.argtypes = [POINTER(vscf_chunk_cipher_t), POINTER(vsc_buffer_t)]
        vscf_chunk_cipher_finish_encryption.restype = c_int
        return vscf_chunk_cipher_finish_encryption(ctx, out)

    def vscf_chunk_cipher_decryption_out_len(self, ctx, data_len):
        """Return buffer length required to hold output of process_decryption and finish_decryption."""
        vscf_chunk_cipher_decryption_out_len = self._lib.vscf_chunk_cipher_decryption_out_len
        vscf_chunk_cipher_decryption_out_len.argtypes = [POINTER(vscf_chunk_cipher_t), c_size_t]
        vscf_chunk_cipher_decryption_out_len.restype = c_size_t
        return vscf_chunk_cipher_decryption_out_len(ctx, data_len)

    def vscf_chunk_cipher_start_decryption(self, ctx):
        """Initiate decryption. Caller must call set_nonce with the initial nonce from CMS before this."""
        vscf_chunk_cipher_start_decryption = self._lib.vscf_chunk_cipher_start_decryption
        vscf_chunk_cipher_start_decryption.argtypes = [POINTER(vscf_chunk_cipher_t)]
        vscf_chunk_cipher_start_decryption.restype = c_int
        return vscf_chunk_cipher_start_decryption(ctx)

    def vscf_chunk_cipher_process_decryption(self, ctx, data, out):
        """Process decryption of a new portion of data."""
        vscf_chunk_cipher_process_decryption = self._lib.vscf_chunk_cipher_process_decryption
        vscf_chunk_cipher_process_decryption.argtypes = [POINTER(vscf_chunk_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_chunk_cipher_process_decryption.restype = c_int
        return vscf_chunk_cipher_process_decryption(ctx, data, out)

    def vscf_chunk_cipher_finish_decryption(self, ctx, out):
        """Decrypt any remaining pending data and finalize the stream."""
        vscf_chunk_cipher_finish_decryption = self._lib.vscf_chunk_cipher_finish_decryption
        vscf_chunk_cipher_finish_decryption.argtypes = [POINTER(vscf_chunk_cipher_t), POINTER(vsc_buffer_t)]
        vscf_chunk_cipher_finish_decryption.restype = c_int
        return vscf_chunk_cipher_finish_decryption(ctx, out)

    def vscf_chunk_cipher_chunk_count(self, ctx, data_len):
        """Return the number of frames the sequential encryption path emits for a plaintext of the
given length: floor(data_len / chunk_size) + 1. The trailing frame (the one with is_last=true)
is empty when data_len is an exact multiple of chunk_size. Use this to drive random-access /
parallel encryption via encrypt_at over indices 0 .. chunk_count-1, placing is_last on the
highest index. Requires chunk_size to be set (> 0)."""
        vscf_chunk_cipher_chunk_count = self._lib.vscf_chunk_cipher_chunk_count
        vscf_chunk_cipher_chunk_count.argtypes = [POINTER(vscf_chunk_cipher_t), c_size_t]
        vscf_chunk_cipher_chunk_count.restype = c_size_t
        return vscf_chunk_cipher_chunk_count(ctx, data_len)

    def vscf_chunk_cipher_encrypt_at(self, ctx, chunk_index, is_last, plaintext, out):
        """Encrypt a single chunk at an explicit index for random-access / parallel encryption, writing
the frame counter_le64[8] | ciphertext | tag[16]. Independent of the start/process/finish
state machine; requires key, initial nonce, and chunk_size to be set, and the instance to be
in the INITIAL state (call before, or instead of, start_encryption).

WARNING (nonce safety): each chunk_index must be encrypted at most ONCE per (key, initial_nonce);
AES-GCM nonce reuse is catastrophic. This API is per-call and does NOT track or enforce
uniqueness — the caller owns it. Thread-safe: each call uses a per-call local cipher context and
only reads the instance's key/nonce/chunk_size, so a single configured instance may be used
concurrently from multiple threads for parallel encryption (no shared mutable cipher state, no
lock). Whole-file only: the caller must know the total chunk count (see chunk_count) to place
exactly one is_last frame."""
        vscf_chunk_cipher_encrypt_at = self._lib.vscf_chunk_cipher_encrypt_at
        vscf_chunk_cipher_encrypt_at.argtypes = [POINTER(vscf_chunk_cipher_t), c_uint, c_bool, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_chunk_cipher_encrypt_at.restype = c_int
        return vscf_chunk_cipher_encrypt_at(ctx, chunk_index, is_last, plaintext, out)

    def vscf_chunk_cipher_decrypt_at(self, ctx, chunk_index, is_last, frame, out):
        """Authenticate and decrypt a single frame as an explicit chunk index for random-access reads.
The frame's embedded counter is validated against the passed-in chunk_index (a mismatch returns
ERROR_BAD_ENCRYPTED_DATA), so callers must pass the true positional index and never trust the
frame's own counter. Independent of the streaming state machine; requires key, initial nonce,
and chunk_size to be set, and the instance to be in the INITIAL state.

Thread-safe: uses a per-call local cipher context and only reads the instance's
key/nonce/chunk_size, so a single configured instance may be used concurrently from multiple
threads for parallel/random-access decryption (no shared mutable cipher state, no lock). Note:
this authenticates which frame is last (is_last) and each frame's position, but not the total
number of frames — protect against truncation by authenticating the chunk count out of band
(or deriving it from the ciphertext length)."""
        vscf_chunk_cipher_decrypt_at = self._lib.vscf_chunk_cipher_decrypt_at
        vscf_chunk_cipher_decrypt_at.argtypes = [POINTER(vscf_chunk_cipher_t), c_uint, c_bool, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_chunk_cipher_decrypt_at.restype = c_int
        return vscf_chunk_cipher_decrypt_at(ctx, chunk_index, is_last, frame, out)

    def vscf_chunk_cipher_shallow_copy(self, ctx):
        vscf_chunk_cipher_shallow_copy = self._lib.vscf_chunk_cipher_shallow_copy
        vscf_chunk_cipher_shallow_copy.argtypes = [POINTER(vscf_chunk_cipher_t)]
        vscf_chunk_cipher_shallow_copy.restype = POINTER(vscf_chunk_cipher_t)
        return vscf_chunk_cipher_shallow_copy(ctx)
