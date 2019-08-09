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
from ._c_bridge import VscfPkcs5Pbes2
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from .alg import Alg
from .encrypt import Encrypt
from .decrypt import Decrypt


class Pkcs5Pbes2(Alg, Encrypt, Decrypt):
    """Virgil Security implementation of the PBES2 (RFC 8018) algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_pkcs5_pbes2 = VscfPkcs5Pbes2()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_delete(self.ctx)

    def set_kdf(self, kdf):
        self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_use_kdf(self.ctx, kdf.c_impl)

    def set_cipher(self, cipher):
        self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_use_cipher(self.ctx, cipher.c_impl)

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def encrypt(self, data):
        """Encrypt given data."""
        d_data = Data(data)
        out = Buffer(self.encrypted_len(data_len=len(data)))
        status = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_encrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def encrypted_len(self, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        result = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_encrypted_len(self.ctx, data_len)
        return result

    def decrypt(self, data):
        """Decrypt given data."""
        d_data = Data(data)
        out = Buffer(self.decrypted_len(data_len=len(data)))
        status = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_decrypt(self.ctx, d_data.data, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def decrypted_len(self, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        result = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_decrypted_len(self.ctx, data_len)
        return result

    def reset(self, pwd):
        """Configure cipher with a new password."""
        d_pwd = Data(pwd)
        self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_reset(self.ctx, d_pwd.data)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_pkcs5_pbes2 = VscfPkcs5Pbes2()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_pkcs5_pbes2 = VscfPkcs5Pbes2()
        inst.ctx = inst._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_shallow_copy(value)
        self._c_impl = self._lib_vscf_pkcs5_pbes2.vscf_pkcs5_pbes2_impl(self.ctx)
