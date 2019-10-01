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


class vscf_pkcs5_pbes2_t(Structure):
    pass


class VscfPkcs5Pbes2(object):
    """Virgil Security implementation of the PBES2 (RFC 8018) algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_pkcs5_pbes2_new(self):
        vscf_pkcs5_pbes2_new = self._lib.vscf_pkcs5_pbes2_new
        vscf_pkcs5_pbes2_new.argtypes = []
        vscf_pkcs5_pbes2_new.restype = POINTER(vscf_pkcs5_pbes2_t)
        return vscf_pkcs5_pbes2_new()

    def vscf_pkcs5_pbes2_delete(self, ctx):
        vscf_pkcs5_pbes2_delete = self._lib.vscf_pkcs5_pbes2_delete
        vscf_pkcs5_pbes2_delete.argtypes = [POINTER(vscf_pkcs5_pbes2_t)]
        vscf_pkcs5_pbes2_delete.restype = None
        return vscf_pkcs5_pbes2_delete(ctx)

    def vscf_pkcs5_pbes2_use_kdf(self, ctx, kdf):
        vscf_pkcs5_pbes2_use_kdf = self._lib.vscf_pkcs5_pbes2_use_kdf
        vscf_pkcs5_pbes2_use_kdf.argtypes = [POINTER(vscf_pkcs5_pbes2_t), POINTER(vscf_impl_t)]
        vscf_pkcs5_pbes2_use_kdf.restype = None
        return vscf_pkcs5_pbes2_use_kdf(ctx, kdf)

    def vscf_pkcs5_pbes2_use_cipher(self, ctx, cipher):
        vscf_pkcs5_pbes2_use_cipher = self._lib.vscf_pkcs5_pbes2_use_cipher
        vscf_pkcs5_pbes2_use_cipher.argtypes = [POINTER(vscf_pkcs5_pbes2_t), POINTER(vscf_impl_t)]
        vscf_pkcs5_pbes2_use_cipher.restype = None
        return vscf_pkcs5_pbes2_use_cipher(ctx, cipher)

    def vscf_pkcs5_pbes2_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_pkcs5_pbes2_alg_id = self._lib.vscf_pkcs5_pbes2_alg_id
        vscf_pkcs5_pbes2_alg_id.argtypes = [POINTER(vscf_pkcs5_pbes2_t)]
        vscf_pkcs5_pbes2_alg_id.restype = c_int
        return vscf_pkcs5_pbes2_alg_id(ctx)

    def vscf_pkcs5_pbes2_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_pkcs5_pbes2_produce_alg_info = self._lib.vscf_pkcs5_pbes2_produce_alg_info
        vscf_pkcs5_pbes2_produce_alg_info.argtypes = [POINTER(vscf_pkcs5_pbes2_t)]
        vscf_pkcs5_pbes2_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_pkcs5_pbes2_produce_alg_info(ctx)

    def vscf_pkcs5_pbes2_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_pkcs5_pbes2_restore_alg_info = self._lib.vscf_pkcs5_pbes2_restore_alg_info
        vscf_pkcs5_pbes2_restore_alg_info.argtypes = [POINTER(vscf_pkcs5_pbes2_t), POINTER(vscf_impl_t)]
        vscf_pkcs5_pbes2_restore_alg_info.restype = c_int
        return vscf_pkcs5_pbes2_restore_alg_info(ctx, alg_info)

    def vscf_pkcs5_pbes2_encrypt(self, ctx, data, out):
        """Encrypt given data."""
        vscf_pkcs5_pbes2_encrypt = self._lib.vscf_pkcs5_pbes2_encrypt
        vscf_pkcs5_pbes2_encrypt.argtypes = [POINTER(vscf_pkcs5_pbes2_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_pkcs5_pbes2_encrypt.restype = c_int
        return vscf_pkcs5_pbes2_encrypt(ctx, data, out)

    def vscf_pkcs5_pbes2_encrypted_len(self, ctx, data_len):
        """Calculate required buffer length to hold the encrypted data."""
        vscf_pkcs5_pbes2_encrypted_len = self._lib.vscf_pkcs5_pbes2_encrypted_len
        vscf_pkcs5_pbes2_encrypted_len.argtypes = [POINTER(vscf_pkcs5_pbes2_t), c_size_t]
        vscf_pkcs5_pbes2_encrypted_len.restype = c_size_t
        return vscf_pkcs5_pbes2_encrypted_len(ctx, data_len)

    def vscf_pkcs5_pbes2_precise_encrypted_len(self, ctx, data_len):
        """Precise length calculation of encrypted data."""
        vscf_pkcs5_pbes2_precise_encrypted_len = self._lib.vscf_pkcs5_pbes2_precise_encrypted_len
        vscf_pkcs5_pbes2_precise_encrypted_len.argtypes = [POINTER(vscf_pkcs5_pbes2_t), c_size_t]
        vscf_pkcs5_pbes2_precise_encrypted_len.restype = c_size_t
        return vscf_pkcs5_pbes2_precise_encrypted_len(ctx, data_len)

    def vscf_pkcs5_pbes2_decrypt(self, ctx, data, out):
        """Decrypt given data."""
        vscf_pkcs5_pbes2_decrypt = self._lib.vscf_pkcs5_pbes2_decrypt
        vscf_pkcs5_pbes2_decrypt.argtypes = [POINTER(vscf_pkcs5_pbes2_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_pkcs5_pbes2_decrypt.restype = c_int
        return vscf_pkcs5_pbes2_decrypt(ctx, data, out)

    def vscf_pkcs5_pbes2_decrypted_len(self, ctx, data_len):
        """Calculate required buffer length to hold the decrypted data."""
        vscf_pkcs5_pbes2_decrypted_len = self._lib.vscf_pkcs5_pbes2_decrypted_len
        vscf_pkcs5_pbes2_decrypted_len.argtypes = [POINTER(vscf_pkcs5_pbes2_t), c_size_t]
        vscf_pkcs5_pbes2_decrypted_len.restype = c_size_t
        return vscf_pkcs5_pbes2_decrypted_len(ctx, data_len)

    def vscf_pkcs5_pbes2_reset(self, ctx, pwd):
        """Configure cipher with a new password."""
        vscf_pkcs5_pbes2_reset = self._lib.vscf_pkcs5_pbes2_reset
        vscf_pkcs5_pbes2_reset.argtypes = [POINTER(vscf_pkcs5_pbes2_t), vsc_data_t]
        vscf_pkcs5_pbes2_reset.restype = None
        return vscf_pkcs5_pbes2_reset(ctx, pwd)

    def vscf_pkcs5_pbes2_shallow_copy(self, ctx):
        vscf_pkcs5_pbes2_shallow_copy = self._lib.vscf_pkcs5_pbes2_shallow_copy
        vscf_pkcs5_pbes2_shallow_copy.argtypes = [POINTER(vscf_pkcs5_pbes2_t)]
        vscf_pkcs5_pbes2_shallow_copy.restype = POINTER(vscf_pkcs5_pbes2_t)
        return vscf_pkcs5_pbes2_shallow_copy(ctx)

    def vscf_pkcs5_pbes2_impl(self, ctx):
        vscf_pkcs5_pbes2_impl = self._lib.vscf_pkcs5_pbes2_impl
        vscf_pkcs5_pbes2_impl.argtypes = [POINTER(vscf_pkcs5_pbes2_t)]
        vscf_pkcs5_pbes2_impl.restype = POINTER(vscf_impl_t)
        return vscf_pkcs5_pbes2_impl(ctx)
