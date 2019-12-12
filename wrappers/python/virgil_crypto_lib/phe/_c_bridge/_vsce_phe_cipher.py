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
from virgil_crypto_lib.foundation._c_bridge._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vsce_phe_cipher_t(Structure):
    pass


class VscePheCipher(object):
    """Class for encryption using PHE account key
    This class is thread-safe."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.phe

    def vsce_phe_cipher_new(self):
        vsce_phe_cipher_new = self._lib.vsce_phe_cipher_new
        vsce_phe_cipher_new.argtypes = []
        vsce_phe_cipher_new.restype = POINTER(vsce_phe_cipher_t)
        return vsce_phe_cipher_new()

    def vsce_phe_cipher_delete(self, ctx):
        vsce_phe_cipher_delete = self._lib.vsce_phe_cipher_delete
        vsce_phe_cipher_delete.argtypes = [POINTER(vsce_phe_cipher_t)]
        vsce_phe_cipher_delete.restype = None
        return vsce_phe_cipher_delete(ctx)

    def vsce_phe_cipher_use_random(self, ctx, random):
        """Random used for salt generation"""
        vsce_phe_cipher_use_random = self._lib.vsce_phe_cipher_use_random
        vsce_phe_cipher_use_random.argtypes = [POINTER(vsce_phe_cipher_t), POINTER(vscf_impl_t)]
        vsce_phe_cipher_use_random.restype = None
        return vsce_phe_cipher_use_random(ctx, random)

    def vsce_phe_cipher_setup_defaults(self, ctx):
        """Setups dependencies with default values."""
        vsce_phe_cipher_setup_defaults = self._lib.vsce_phe_cipher_setup_defaults
        vsce_phe_cipher_setup_defaults.argtypes = [POINTER(vsce_phe_cipher_t)]
        vsce_phe_cipher_setup_defaults.restype = c_int
        return vsce_phe_cipher_setup_defaults(ctx)

    def vsce_phe_cipher_encrypt_len(self, ctx, plain_text_len):
        """Returns buffer capacity needed to fit cipher text"""
        vsce_phe_cipher_encrypt_len = self._lib.vsce_phe_cipher_encrypt_len
        vsce_phe_cipher_encrypt_len.argtypes = [POINTER(vsce_phe_cipher_t), c_size_t]
        vsce_phe_cipher_encrypt_len.restype = c_size_t
        return vsce_phe_cipher_encrypt_len(ctx, plain_text_len)

    def vsce_phe_cipher_decrypt_len(self, ctx, cipher_text_len):
        """Returns buffer capacity needed to fit plain text"""
        vsce_phe_cipher_decrypt_len = self._lib.vsce_phe_cipher_decrypt_len
        vsce_phe_cipher_decrypt_len.argtypes = [POINTER(vsce_phe_cipher_t), c_size_t]
        vsce_phe_cipher_decrypt_len.restype = c_size_t
        return vsce_phe_cipher_decrypt_len(ctx, cipher_text_len)

    def vsce_phe_cipher_encrypt(self, ctx, plain_text, account_key, cipher_text):
        """Encrypts data using account key"""
        vsce_phe_cipher_encrypt = self._lib.vsce_phe_cipher_encrypt
        vsce_phe_cipher_encrypt.argtypes = [POINTER(vsce_phe_cipher_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_cipher_encrypt.restype = c_int
        return vsce_phe_cipher_encrypt(ctx, plain_text, account_key, cipher_text)

    def vsce_phe_cipher_decrypt(self, ctx, cipher_text, account_key, plain_text):
        """Decrypts data using account key"""
        vsce_phe_cipher_decrypt = self._lib.vsce_phe_cipher_decrypt
        vsce_phe_cipher_decrypt.argtypes = [POINTER(vsce_phe_cipher_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_cipher_decrypt.restype = c_int
        return vsce_phe_cipher_decrypt(ctx, cipher_text, account_key, plain_text)

    def vsce_phe_cipher_auth_encrypt(self, ctx, plain_text, additional_data, account_key, cipher_text):
        """Encrypts data (and authenticates additional data) using account key"""
        vsce_phe_cipher_auth_encrypt = self._lib.vsce_phe_cipher_auth_encrypt
        vsce_phe_cipher_auth_encrypt.argtypes = [POINTER(vsce_phe_cipher_t), vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_cipher_auth_encrypt.restype = c_int
        return vsce_phe_cipher_auth_encrypt(ctx, plain_text, additional_data, account_key, cipher_text)

    def vsce_phe_cipher_auth_decrypt(self, ctx, cipher_text, additional_data, account_key, plain_text):
        """Decrypts data (and verifies additional data) using account key"""
        vsce_phe_cipher_auth_decrypt = self._lib.vsce_phe_cipher_auth_decrypt
        vsce_phe_cipher_auth_decrypt.argtypes = [POINTER(vsce_phe_cipher_t), vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_cipher_auth_decrypt.restype = c_int
        return vsce_phe_cipher_auth_decrypt(ctx, cipher_text, additional_data, account_key, plain_text)

    def vsce_phe_cipher_shallow_copy(self, ctx):
        vsce_phe_cipher_shallow_copy = self._lib.vsce_phe_cipher_shallow_copy
        vsce_phe_cipher_shallow_copy.argtypes = [POINTER(vsce_phe_cipher_t)]
        vsce_phe_cipher_shallow_copy.restype = POINTER(vsce_phe_cipher_t)
        return vsce_phe_cipher_shallow_copy(ctx)
