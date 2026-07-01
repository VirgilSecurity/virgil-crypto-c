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


from ctypes import *
from ._c_bridge import VscfChunkCipher
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from .alg import Alg
from .encrypt import Encrypt
from .decrypt import Decrypt
from .cipher_info import CipherInfo
from .cipher import Cipher


class ChunkCipher(Alg, Encrypt, Decrypt, CipherInfo, Cipher):
    """Provides stream encryption in fixed-size chunks, where each encrypted
chunk carries its own AES-256-GCM authentication tag.

Nonce derivation follows the TLS 1.3 construction:
    nonce_i = initial_nonce XOR (0x00000000 || uint64_be(i))

Each encrypted frame layout:
    counter_le64[8] | ciphertext[N] | tag[16]

The construction is self-describing: it produces and restores a
'chunked alg info' (algorithm id 'aes256 gcm chunked' carrying version,
chunk size, and the initial nonce) via the 'alg' interface, so the
generic decryptor (recipient cipher / alg factory) can reconstruct and
drive it through the 'cipher' interface without out-of-band parameters."""

    # Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    NONCE_LEN = 12
    # Cipher key length in bytes.
    KEY_LEN = 32
    # Cipher key length in bits.
    KEY_BITLEN = 256
    # Cipher block length in bytes.
    BLOCK_LEN = 16

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_chunk_cipher = VscfChunkCipher()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_use_random(self.ctx, random.c_impl)

    def set_chunk_size(self, chunk_size):
        """Set the plaintext chunk size in bytes. Default is 65536."""
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_set_chunk_size(self.ctx, chunk_size)

    def nonce(self):
        """Return the 12-byte initial nonce.
Valid after calling start_encryption; store in CMS custom params for decryption."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_nonce(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def nonce_len(self):
        """Return nonce length in bytes (always 12)."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_nonce_len(self.ctx)
        return result

    def encryption_out_len(self, data_len):
        """Return buffer length required to hold output of process_encryption and finish_encryption."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_encryption_out_len(self.ctx, data_len)
        return result

    def process_encryption(self, data):
        """Process encryption of a new portion of data."""
        d_data = Data(data)
        out = Buffer(self.encryption_out_len(data_len=len(data)))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_process_encryption(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def finish_encryption(self):
        """Encrypt any remaining pending data and finalize the stream."""
        out = Buffer(self.encryption_out_len(0))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_finish_encryption(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decryption_out_len(self, data_len):
        """Return buffer length required to hold output of process_decryption and finish_decryption."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_decryption_out_len(self.ctx, data_len)
        return result

    def process_decryption(self, data):
        """Process decryption of a new portion of data."""
        d_data = Data(data)
        out = Buffer(self.decryption_out_len(data_len=len(data)))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_process_decryption(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def finish_decryption(self):
        """Decrypt any remaining pending data and finalize the stream."""
        out = Buffer(self.decryption_out_len(0))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_finish_decryption(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def chunk_count(self, data_len):
        """Return the number of frames the sequential encryption path emits for a plaintext of the
given length: floor(data_len / chunk_size) + 1. The trailing frame (the one with is_last=true)
is empty when data_len is an exact multiple of chunk_size. Use this to drive random-access /
parallel encryption via encrypt_at over indices 0 .. chunk_count-1, placing is_last on the
highest index. Requires chunk_size to be set (> 0)."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_chunk_count(self.ctx, data_len)
        return result

    def encrypt_at(self, chunk_index, is_last, plaintext):
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
        d_plaintext = Data(plaintext)
        out = Buffer(self.encryption_out_len(data_len=len(plaintext)))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_encrypt_at(self.ctx, chunk_index, is_last, d_plaintext.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypt_at(self, chunk_index, is_last, frame):
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
        d_frame = Data(frame)
        out = Buffer(self.decryption_out_len(data_len=len(frame)))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_decrypt_at(self.ctx, chunk_index, is_last, d_frame.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def set_nonce(self, nonce):
        """Set the 12-byte initial nonce. On encryption this is honored (not
regenerated) by start_encryption; on decryption it is required."""
        d_nonce = Data(nonce)
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_set_nonce(self.ctx, d_nonce.data)

    def set_key(self, key):
        """Set the 32-byte AES-256 encryption key."""
        d_key = Data(key)
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_set_key(self.ctx, d_key.data)

    def start_encryption(self):
        """Initiate encryption. Generates a random 12-byte initial nonce only if
one was not already set (via set_nonce or restore_alg_info), so an
injected nonce is honored. An RNG failure is captured and surfaced
from the first process_encryption/update/finish call."""
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_start_encryption(self.ctx)

    def start_decryption(self):
        """Initiate decryption. Caller must set the initial nonce (via set_nonce
or restore_alg_info) before this."""
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_start_decryption(self.ctx)

    def update(self, data):
        """Process encryption or decryption of the given data chunk.
Dispatches to the framed encryption or decryption path depending on
the current state."""
        d_data = Data(data)
        out = Buffer(self.out_len(data_len=len(data)))
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_update(self.ctx, d_data.data, out.c_buffer)
        return out.get_bytes()

    def out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
"update" or "finish" in an current mode.
Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_out_len(self.ctx, data_len)
        return result

    def encrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
"update" or "finish" in an encryption mode.
Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_encrypted_out_len(self.ctx, data_len)
        return result

    def decrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
"update" or "finish" in an decryption mode.
Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_decrypted_out_len(self.ctx, data_len)
        return result

    def finish(self):
        """Accomplish encryption or decryption process.
Dispatches to finish_encryption or finish_decryption depending on
the current state."""
        out = Buffer(self.out_len(0))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_finish(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def encrypt(self, data):
        """Encrypt given data."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(data_len=len(data)))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_encrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def encrypted_len(self, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_encrypted_len(self.ctx, data_len)
        return result

    def precise_encrypted_len(self, data_len):
        """Precise length calculation of encrypted data."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_precise_encrypted_len(self.ctx, data_len)
        return result

    def decrypt(self, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(data_len=len(data)))
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_decrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypted_len(self, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_decrypted_len(self.ctx, data_len)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_chunk_cipher = VscfChunkCipher()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_chunk_cipher = VscfChunkCipher()
        inst.ctx = inst._lib_vscf_chunk_cipher.vscf_chunk_cipher_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_shallow_copy(value)
        self._c_impl = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_impl(self.ctx)
