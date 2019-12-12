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
from ._c_bridge import VscePheCipher
from ._c_bridge import VsceStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer


class Cipher(object):
    """Class for encryption using PHE account key
    This class is thread-safe."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsce_phe_cipher = VscePheCipher()
        self.ctx = self._lib_vsce_phe_cipher.vsce_phe_cipher_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsce_phe_cipher.vsce_phe_cipher_delete(self.ctx)

    def set_random(self, random):
        """Random used for salt generation"""
        self._lib_vsce_phe_cipher.vsce_phe_cipher_use_random(self.ctx, random.c_impl)

    def setup_defaults(self):
        """Setups dependencies with default values."""
        status = self._lib_vsce_phe_cipher.vsce_phe_cipher_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def encrypt_len(self, plain_text_len):
        """Returns buffer capacity needed to fit cipher text"""
        result = self._lib_vsce_phe_cipher.vsce_phe_cipher_encrypt_len(self.ctx, plain_text_len)
        return result

    def decrypt_len(self, cipher_text_len):
        """Returns buffer capacity needed to fit plain text"""
        result = self._lib_vsce_phe_cipher.vsce_phe_cipher_decrypt_len(self.ctx, cipher_text_len)
        return result

    def encrypt(self, plain_text, account_key):
        """Encrypts data using account key"""
        d_plain_text = Data(plain_text)
        d_account_key = Data(account_key)
        cipher_text = Buffer(self.encrypt_len(plain_text_len=len(plain_text)))
        status = self._lib_vsce_phe_cipher.vsce_phe_cipher_encrypt(self.ctx, d_plain_text.data, d_account_key.data, cipher_text.c_buffer)
        VsceStatus.handle_status(status)
        return cipher_text.get_bytes()

    def decrypt(self, cipher_text, account_key):
        """Decrypts data using account key"""
        d_cipher_text = Data(cipher_text)
        d_account_key = Data(account_key)
        plain_text = Buffer(self.decrypt_len(cipher_text_len=len(cipher_text)))
        status = self._lib_vsce_phe_cipher.vsce_phe_cipher_decrypt(self.ctx, d_cipher_text.data, d_account_key.data, plain_text.c_buffer)
        VsceStatus.handle_status(status)
        return plain_text.get_bytes()

    def auth_encrypt(self, plain_text, additional_data, account_key):
        """Encrypts data (and authenticates additional data) using account key"""
        d_plain_text = Data(plain_text)
        d_additional_data = Data(additional_data)
        d_account_key = Data(account_key)
        cipher_text = Buffer(self.encrypt_len(plain_text_len=len(plain_text)))
        status = self._lib_vsce_phe_cipher.vsce_phe_cipher_auth_encrypt(self.ctx, d_plain_text.data, d_additional_data.data, d_account_key.data, cipher_text.c_buffer)
        VsceStatus.handle_status(status)
        return cipher_text.get_bytes()

    def auth_decrypt(self, cipher_text, additional_data, account_key):
        """Decrypts data (and verifies additional data) using account key"""
        d_cipher_text = Data(cipher_text)
        d_additional_data = Data(additional_data)
        d_account_key = Data(account_key)
        plain_text = Buffer(self.decrypt_len(cipher_text_len=len(cipher_text)))
        status = self._lib_vsce_phe_cipher.vsce_phe_cipher_auth_decrypt(self.ctx, d_cipher_text.data, d_additional_data.data, d_account_key.data, plain_text.c_buffer)
        VsceStatus.handle_status(status)
        return plain_text.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_phe_cipher = VscePheCipher()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_phe_cipher = VscePheCipher()
        inst.ctx = inst._lib_vsce_phe_cipher.vsce_phe_cipher_shallow_copy(c_ctx)
        return inst
