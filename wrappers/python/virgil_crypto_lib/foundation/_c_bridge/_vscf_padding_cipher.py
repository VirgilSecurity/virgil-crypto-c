# Copyright (C) 2015-2019 Virgil Security, Inc.
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


class vscf_padding_cipher_t(Structure):
    pass


class VscfPaddingCipher(object):
    """Wraps any symmetric cipher algorithm to add padding to plaintext
    to prevent message guessing attacks based on a ciphertext length."""

    PADDING_FRAME_DEFAULT = 160
    PADDING_FRAME_MIN = 32
    PADDING_FRAME_MAX = 8 * 1024
    PADDING_SIZE_LEN = 4
    PADDING_LEN_MIN = vscf_padding_cipher_PADDING_SIZE_LEN + 1

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_padding_cipher_new(self):
        vscf_padding_cipher_new = self._lib.vscf_padding_cipher_new
        vscf_padding_cipher_new.argtypes = []
        vscf_padding_cipher_new.restype = POINTER(vscf_padding_cipher_t)
        return vscf_padding_cipher_new()

    def vscf_padding_cipher_delete(self, ctx):
        vscf_padding_cipher_delete = self._lib.vscf_padding_cipher_delete
        vscf_padding_cipher_delete.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_delete.restype = None
        return vscf_padding_cipher_delete(ctx)

    def vscf_padding_cipher_use_random(self, ctx, random):
        vscf_padding_cipher_use_random = self._lib.vscf_padding_cipher_use_random
        vscf_padding_cipher_use_random.argtypes = [POINTER(vscf_padding_cipher_t), POINTER(vscf_impl_t)]
        vscf_padding_cipher_use_random.restype = None
        return vscf_padding_cipher_use_random(ctx, random)

    def vscf_padding_cipher_use_cipher(self, ctx, cipher):
        vscf_padding_cipher_use_cipher = self._lib.vscf_padding_cipher_use_cipher
        vscf_padding_cipher_use_cipher.argtypes = [POINTER(vscf_padding_cipher_t), POINTER(vscf_impl_t)]
        vscf_padding_cipher_use_cipher.restype = None
        return vscf_padding_cipher_use_cipher(ctx, cipher)

    def vscf_padding_cipher_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_padding_cipher_alg_id = self._lib.vscf_padding_cipher_alg_id
        vscf_padding_cipher_alg_id.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_alg_id.restype = c_int
        return vscf_padding_cipher_alg_id(ctx)

    def vscf_padding_cipher_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_padding_cipher_produce_alg_info = self._lib.vscf_padding_cipher_produce_alg_info
        vscf_padding_cipher_produce_alg_info.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_padding_cipher_produce_alg_info(ctx)

    def vscf_padding_cipher_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_padding_cipher_restore_alg_info = self._lib.vscf_padding_cipher_restore_alg_info
        vscf_padding_cipher_restore_alg_info.argtypes = [POINTER(vscf_padding_cipher_t), POINTER(vscf_impl_t)]
        vscf_padding_cipher_restore_alg_info.restype = c_int
        return vscf_padding_cipher_restore_alg_info(ctx, alg_info)

    def vscf_padding_cipher_encrypt(self, ctx, data, out):
        """Encrypt given data."""
        vscf_padding_cipher_encrypt = self._lib.vscf_padding_cipher_encrypt
        vscf_padding_cipher_encrypt.argtypes = [POINTER(vscf_padding_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_padding_cipher_encrypt.restype = c_int
        return vscf_padding_cipher_encrypt(ctx, data, out)

    def vscf_padding_cipher_encrypted_len(self, ctx, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        vscf_padding_cipher_encrypted_len = self._lib.vscf_padding_cipher_encrypted_len
        vscf_padding_cipher_encrypted_len.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_encrypted_len.restype = c_size_t
        return vscf_padding_cipher_encrypted_len(ctx, data_len)

    def vscf_padding_cipher_precise_encrypted_len(self, ctx, data_len):
        """Precise length calculation of encrypted data."""
        vscf_padding_cipher_precise_encrypted_len = self._lib.vscf_padding_cipher_precise_encrypted_len
        vscf_padding_cipher_precise_encrypted_len.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_precise_encrypted_len.restype = c_size_t
        return vscf_padding_cipher_precise_encrypted_len(ctx, data_len)

    def vscf_padding_cipher_decrypt(self, ctx, data, out):
        """Decrypt given data."""
        vscf_padding_cipher_decrypt = self._lib.vscf_padding_cipher_decrypt
        vscf_padding_cipher_decrypt.argtypes = [POINTER(vscf_padding_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_padding_cipher_decrypt.restype = c_int
        return vscf_padding_cipher_decrypt(ctx, data, out)

    def vscf_padding_cipher_decrypted_len(self, ctx, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        vscf_padding_cipher_decrypted_len = self._lib.vscf_padding_cipher_decrypted_len
        vscf_padding_cipher_decrypted_len.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_decrypted_len.restype = c_size_t
        return vscf_padding_cipher_decrypted_len(ctx, data_len)

    def vscf_padding_cipher_nonce_len(self, ctx):
        """Return cipher's nonce length or IV length in bytes,
        or 0 if nonce is not required."""
        vscf_padding_cipher_nonce_len = self._lib.vscf_padding_cipher_nonce_len
        vscf_padding_cipher_nonce_len.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_nonce_len.restype = c_size_t
        return vscf_padding_cipher_nonce_len(ctx)

    def vscf_padding_cipher_key_len(self, ctx):
        """Return cipher's key length in bytes."""
        vscf_padding_cipher_key_len = self._lib.vscf_padding_cipher_key_len
        vscf_padding_cipher_key_len.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_key_len.restype = c_size_t
        return vscf_padding_cipher_key_len(ctx)

    def vscf_padding_cipher_key_bitlen(self, ctx):
        """Return cipher's key length in bits."""
        vscf_padding_cipher_key_bitlen = self._lib.vscf_padding_cipher_key_bitlen
        vscf_padding_cipher_key_bitlen.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_key_bitlen.restype = c_size_t
        return vscf_padding_cipher_key_bitlen(ctx)

    def vscf_padding_cipher_block_len(self, ctx):
        """Return cipher's block length in bytes."""
        vscf_padding_cipher_block_len = self._lib.vscf_padding_cipher_block_len
        vscf_padding_cipher_block_len.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_block_len.restype = c_size_t
        return vscf_padding_cipher_block_len(ctx)

    def vscf_padding_cipher_set_nonce(self, ctx, nonce):
        """Setup IV or nonce."""
        vscf_padding_cipher_set_nonce = self._lib.vscf_padding_cipher_set_nonce
        vscf_padding_cipher_set_nonce.argtypes = [POINTER(vscf_padding_cipher_t), vsc_data_t]
        vscf_padding_cipher_set_nonce.restype = None
        return vscf_padding_cipher_set_nonce(ctx, nonce)

    def vscf_padding_cipher_set_key(self, ctx, key):
        """Set cipher encryption / decryption key."""
        vscf_padding_cipher_set_key = self._lib.vscf_padding_cipher_set_key
        vscf_padding_cipher_set_key.argtypes = [POINTER(vscf_padding_cipher_t), vsc_data_t]
        vscf_padding_cipher_set_key.restype = None
        return vscf_padding_cipher_set_key(ctx, key)

    def vscf_padding_cipher_state(self, ctx):
        """Return cipher's current state."""
        vscf_padding_cipher_state = self._lib.vscf_padding_cipher_state
        vscf_padding_cipher_state.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_state.restype = c_int
        return vscf_padding_cipher_state(ctx)

    def vscf_padding_cipher_start_encryption(self, ctx):
        """Start sequential encryption."""
        vscf_padding_cipher_start_encryption = self._lib.vscf_padding_cipher_start_encryption
        vscf_padding_cipher_start_encryption.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_start_encryption.restype = None
        return vscf_padding_cipher_start_encryption(ctx)

    def vscf_padding_cipher_start_decryption(self, ctx):
        """Start sequential decryption."""
        vscf_padding_cipher_start_decryption = self._lib.vscf_padding_cipher_start_decryption
        vscf_padding_cipher_start_decryption.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_start_decryption.restype = None
        return vscf_padding_cipher_start_decryption(ctx)

    def vscf_padding_cipher_update(self, ctx, data, out):
        """Process encryption or decryption of the given data chunk."""
        vscf_padding_cipher_update = self._lib.vscf_padding_cipher_update
        vscf_padding_cipher_update.argtypes = [POINTER(vscf_padding_cipher_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_padding_cipher_update.restype = None
        return vscf_padding_cipher_update(ctx, data, out)

    def vscf_padding_cipher_out_len(self, ctx, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an current mode.
        Pass zero length to define buffer length of the method "finish"."""
        vscf_padding_cipher_out_len = self._lib.vscf_padding_cipher_out_len
        vscf_padding_cipher_out_len.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_out_len.restype = c_size_t
        return vscf_padding_cipher_out_len(ctx, data_len)

    def vscf_padding_cipher_encrypted_out_len(self, ctx, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an encryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        vscf_padding_cipher_encrypted_out_len = self._lib.vscf_padding_cipher_encrypted_out_len
        vscf_padding_cipher_encrypted_out_len.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_encrypted_out_len.restype = c_size_t
        return vscf_padding_cipher_encrypted_out_len(ctx, data_len)

    def vscf_padding_cipher_decrypted_out_len(self, ctx, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an decryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        vscf_padding_cipher_decrypted_out_len = self._lib.vscf_padding_cipher_decrypted_out_len
        vscf_padding_cipher_decrypted_out_len.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_decrypted_out_len.restype = c_size_t
        return vscf_padding_cipher_decrypted_out_len(ctx, data_len)

    def vscf_padding_cipher_finish(self, ctx, out):
        """Accomplish encryption or decryption process."""
        vscf_padding_cipher_finish = self._lib.vscf_padding_cipher_finish
        vscf_padding_cipher_finish.argtypes = [POINTER(vscf_padding_cipher_t), POINTER(vsc_buffer_t)]
        vscf_padding_cipher_finish.restype = c_int
        return vscf_padding_cipher_finish(ctx, out)

    def vscf_padding_cipher_set_padding_frame(self, ctx, padding_frame):
        """Setup padding frame in bytes.
        The padding frame defines the multiplicator of data length."""
        vscf_padding_cipher_set_padding_frame = self._lib.vscf_padding_cipher_set_padding_frame
        vscf_padding_cipher_set_padding_frame.argtypes = [POINTER(vscf_padding_cipher_t), c_size_t]
        vscf_padding_cipher_set_padding_frame.restype = None
        return vscf_padding_cipher_set_padding_frame(ctx, padding_frame)

    def vscf_padding_cipher_shallow_copy(self, ctx):
        vscf_padding_cipher_shallow_copy = self._lib.vscf_padding_cipher_shallow_copy
        vscf_padding_cipher_shallow_copy.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_shallow_copy.restype = POINTER(vscf_padding_cipher_t)
        return vscf_padding_cipher_shallow_copy(ctx)

    def vscf_padding_cipher_impl(self, ctx):
        vscf_padding_cipher_impl = self._lib.vscf_padding_cipher_impl
        vscf_padding_cipher_impl.argtypes = [POINTER(vscf_padding_cipher_t)]
        vscf_padding_cipher_impl.restype = POINTER(vscf_impl_t)
        return vscf_padding_cipher_impl(ctx)
