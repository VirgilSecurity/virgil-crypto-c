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
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer


class ChunkCipher(object):
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
        self._lib_vscf_chunk_cipher = VscfChunkCipher()
        self.ctx = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_use_random(self.ctx, random.c_impl)

    def set_key(self, key):
        """Set the 32-byte AES-256 encryption key."""
        d_key = Data(key)
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_set_key(self.ctx, d_key.data)

    def set_nonce(self, nonce):
        """Set the 12-byte initial nonce for decryption.
Not needed for encryption: nonce is generated automatically in start_encryption."""
        d_nonce = Data(nonce)
        self._lib_vscf_chunk_cipher.vscf_chunk_cipher_set_nonce(self.ctx, d_nonce.data)

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

    def start_encryption(self):
        """Initiate encryption. Generates a random 12-byte initial nonce."""
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_start_encryption(self.ctx)
        VscfStatus.handle_status(status)

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

    def start_decryption(self):
        """Initiate decryption. Caller must call set_nonce with the initial nonce from CMS before this."""
        status = self._lib_vscf_chunk_cipher.vscf_chunk_cipher_start_decryption(self.ctx)
        VscfStatus.handle_status(status)

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
