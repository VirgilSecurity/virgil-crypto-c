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
from ._c_bridge import VscfAes256Cbc
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from .alg import Alg
from .encrypt import Encrypt
from .decrypt import Decrypt
from .cipher_info import CipherInfo
from .cipher import Cipher


class Aes256Cbc(Alg, Encrypt, Decrypt, CipherInfo, Cipher):
    """Implementation of the symmetric cipher AES-256 bit in a CBC mode.
    Note, this implementation contains dynamic memory allocations,
    this should be improved in the future releases."""

    # Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    NONCE_LEN = 16
    # Cipher key length in bytes.
    KEY_LEN = 32
    # Cipher key length in bits.
    KEY_BITLEN = 256
    # Cipher block length in bytes.
    BLOCK_LEN = 16

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_aes256_cbc = VscfAes256Cbc()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_aes256_cbc.vscf_aes256_cbc_delete(self.ctx)

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def encrypt(self, data):
        """Encrypt given data."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(data_len=len(data)))
        status = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_encrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def encrypted_len(self, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_encrypted_len(self.ctx, data_len)
        return result

    def decrypt(self, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(data_len=len(data)))
        status = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_decrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypted_len(self, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_decrypted_len(self.ctx, data_len)
        return result

    def set_nonce(self, nonce):
        """Setup IV or nonce."""
        d_nonce = Data(nonce)
        self._lib_vscf_aes256_cbc.vscf_aes256_cbc_set_nonce(self.ctx, d_nonce.data)

    def set_key(self, key):
        """Set cipher encryption / decryption key."""
        d_key = Data(key)
        self._lib_vscf_aes256_cbc.vscf_aes256_cbc_set_key(self.ctx, d_key.data)

    def start_encryption(self):
        """Start sequential encryption."""
        self._lib_vscf_aes256_cbc.vscf_aes256_cbc_start_encryption(self.ctx)

    def start_decryption(self):
        """Start sequential decryption."""
        self._lib_vscf_aes256_cbc.vscf_aes256_cbc_start_decryption(self.ctx)

    def update(self, data):
        """Process encryption or decryption of the given data chunk."""
        d_data = Data(data)
        out = Buffer(self.out_len(data_len=len(data)))
        self._lib_vscf_aes256_cbc.vscf_aes256_cbc_update(self.ctx, d_data.data, out.c_buffer)
        return out.get_bytes()

    def out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an current mode.
        Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_out_len(self.ctx, data_len)
        return result

    def encrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an encryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_encrypted_out_len(self.ctx, data_len)
        return result

    def decrypted_out_len(self, data_len):
        """Return buffer length required to hold an output of the methods
        "update" or "finish" in an decryption mode.
        Pass zero length to define buffer length of the method "finish"."""
        result = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_decrypted_out_len(self.ctx, data_len)
        return result

    def finish(self):
        """Accomplish encryption or decryption process."""
        out = Buffer(self.out_len(data_len=0))
        status = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_finish(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_aes256_cbc = VscfAes256Cbc()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_aes256_cbc = VscfAes256Cbc()
        inst.ctx = inst._lib_vscf_aes256_cbc.vscf_aes256_cbc_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_shallow_copy(value)
        self._c_impl = self._lib_vscf_aes256_cbc.vscf_aes256_cbc_impl(self.ctx)
