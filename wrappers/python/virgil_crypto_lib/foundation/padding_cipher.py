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


from ctypes import *
from ._c_bridge import VscfPaddingCipher
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus
from .encrypt import Encrypt
from .decrypt import Decrypt
from .cipher_info import CipherInfo
from .cipher import Cipher


class PaddingCipher(Encrypt, Decrypt, CipherInfo, Cipher):
    """Wraps any symmetric cipher algorithm to add padding to plaintext
    to prevent message guessing attacks based on a ciphertext length."""

    PADDING_FRAME_DEFAULT = 160
    PADDING_FRAME_MIN = 32
    PADDING_FRAME_MAX = 8 * 1024
    PADDING_SIZE_LEN = 4
    PADDING_LEN_MIN = vscf_padding_cipher_PADDING_SIZE_LEN + 1

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_padding_cipher = VscfPaddingCipher()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_padding_cipher.vscf_padding_cipher_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_padding_cipher.vscf_padding_cipher_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_padding_cipher.vscf_padding_cipher_use_random(self.ctx, random.c_impl)

    def set_cipher(self, cipher):
        self._lib_vscf_padding_cipher.vscf_padding_cipher_use_cipher(self.ctx, cipher.c_impl)

    def encrypt(self, data):
        """Encrypt given data."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(data_len=len(data)))
        status = self._lib_vscf_padding_cipher.vscf_padding_cipher_encrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def encrypted_len(self, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_encrypted_len(self.ctx, data_len)
        return result

    def precise_encrypted_len(self, data_len):
        """Precise length calculation of encrypted data."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_precise_encrypted_len(self.ctx, data_len)
        return result

    def decrypt(self, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(data_len=len(data)))
        status = self._lib_vscf_padding_cipher.vscf_padding_cipher_decrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypted_len(self, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_decrypted_len(self.ctx, data_len)
        return result

    def nonce_len(self):
        """Return cipher's nonce length or IV length in bytes,
        or 0 if nonce is not required."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_nonce_len(self.ctx)
        return result

    def key_len(self):
        """Return cipher's key length in bytes."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_key_len(self.ctx)
        return result

    def key_bitlen(self):
        """Return cipher's key length in bits."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_key_bitlen(self.ctx)
        return result

    def block_len(self):
        """Return cipher's block length in bytes."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_block_len(self.ctx)
        return result

    def set_nonce(self, nonce):
        """Setup IV or nonce."""
        d_nonce = Data(nonce)
        self._lib_vscf_padding_cipher.vscf_padding_cipher_set_nonce(self.ctx, d_nonce.data)

    def set_key(self, key):
        """Set cipher encryption / decryption key."""
        d_key = Data(key)
        self._lib_vscf_padding_cipher.vscf_padding_cipher_set_key(self.ctx, d_key.data)

    def state(self):
        """Return cipher's current state."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_state(self.ctx)
        return result

    def start_encryption(self):
        """Start sequential encryption."""
        self._lib_vscf_padding_cipher.vscf_padding_cipher_start_encryption(self.ctx)

    def start_decryption(self):
        """Start sequential decryption."""
        self._lib_vscf_padding_cipher.vscf_padding_cipher_start_decryption(self.ctx)

    def update(self, data):
        """Process encryption or decryption of the given data chunk."""
        d_data = Data(data)
        out = Buffer(self.out_len(data_len=len(data)))
        self._lib_vscf_padding_cipher.vscf_padding_cipher_update(self.ctx, d_data.data, out.c_buffer)
        return out.get_bytes()

    def out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an current mode.
        Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_out_len(self.ctx, data_len)
        return result

    def encrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an encryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_encrypted_out_len(self.ctx, data_len)
        return result

    def decrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an decryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_padding_cipher.vscf_padding_cipher_decrypted_out_len(self.ctx, data_len)
        return result

    def finish(self):
        """Accomplish encryption or decryption process."""
        out = Buffer(self.out_len(data_len=0))
        status = self._lib_vscf_padding_cipher.vscf_padding_cipher_finish(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def set_padding_frame(self, padding_frame):
        """Setup padding frame in bytes.
        The padding frame defines the multiplicator of data length."""
        self._lib_vscf_padding_cipher.vscf_padding_cipher_set_padding_frame(self.ctx, padding_frame)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_padding_cipher = VscfPaddingCipher()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_padding_cipher = VscfPaddingCipher()
        inst.ctx = inst._lib_vscf_padding_cipher.vscf_padding_cipher_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_padding_cipher.vscf_padding_cipher_shallow_copy(value)
        self._c_impl = self._lib_vscf_padding_cipher.vscf_padding_cipher_impl(self.ctx)
