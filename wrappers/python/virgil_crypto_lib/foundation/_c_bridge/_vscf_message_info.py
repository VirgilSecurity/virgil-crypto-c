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
from ._vscf_key_recipient_info_list import vscf_key_recipient_info_list_t
from ._vscf_password_recipient_info_list import vscf_password_recipient_info_list_t
from ._vscf_message_info_custom_params import vscf_message_info_custom_params_t
from ._vscf_footer_info import vscf_footer_info_t


class vscf_message_info_t(Structure):
    pass


class VscfMessageInfo(object):
    """Handle information about an encrypted message and algorithms
    that was used for encryption."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_new(self):
        vscf_message_info_new = self._lib.vscf_message_info_new
        vscf_message_info_new.argtypes = []
        vscf_message_info_new.restype = POINTER(vscf_message_info_t)
        return vscf_message_info_new()

    def vscf_message_info_delete(self, ctx):
        vscf_message_info_delete = self._lib.vscf_message_info_delete
        vscf_message_info_delete.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_delete.restype = None
        return vscf_message_info_delete(ctx)

    def vscf_message_info_data_encryption_alg_info(self, ctx):
        """Return information about algorithm that was used for the data encryption."""
        vscf_message_info_data_encryption_alg_info = self._lib.vscf_message_info_data_encryption_alg_info
        vscf_message_info_data_encryption_alg_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_data_encryption_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_message_info_data_encryption_alg_info(ctx)

    def vscf_message_info_key_recipient_info_list(self, ctx):
        """Return list with a "key recipient info" elements."""
        vscf_message_info_key_recipient_info_list = self._lib.vscf_message_info_key_recipient_info_list
        vscf_message_info_key_recipient_info_list.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_key_recipient_info_list.restype = POINTER(vscf_key_recipient_info_list_t)
        return vscf_message_info_key_recipient_info_list(ctx)

    def vscf_message_info_password_recipient_info_list(self, ctx):
        """Return list with a "password recipient info" elements."""
        vscf_message_info_password_recipient_info_list = self._lib.vscf_message_info_password_recipient_info_list
        vscf_message_info_password_recipient_info_list.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_password_recipient_info_list.restype = POINTER(vscf_password_recipient_info_list_t)
        return vscf_message_info_password_recipient_info_list(ctx)

    def vscf_message_info_has_custom_params(self, ctx):
        """Return true if message info contains at least one custom param."""
        vscf_message_info_has_custom_params = self._lib.vscf_message_info_has_custom_params
        vscf_message_info_has_custom_params.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_has_custom_params.restype = c_bool
        return vscf_message_info_has_custom_params(ctx)

    def vscf_message_info_custom_params(self, ctx):
        """Provide access to the custom params object.
        The returned object can be used to add custom params or read it.
        If custom params object was not set then new empty object is created."""
        vscf_message_info_custom_params = self._lib.vscf_message_info_custom_params
        vscf_message_info_custom_params.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_custom_params.restype = POINTER(vscf_message_info_custom_params_t)
        return vscf_message_info_custom_params(ctx)

    def vscf_message_info_has_cipher_kdf_alg_info(self, ctx):
        """Return true if cipher kdf alg info exists."""
        vscf_message_info_has_cipher_kdf_alg_info = self._lib.vscf_message_info_has_cipher_kdf_alg_info
        vscf_message_info_has_cipher_kdf_alg_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_has_cipher_kdf_alg_info.restype = c_bool
        return vscf_message_info_has_cipher_kdf_alg_info(ctx)

    def vscf_message_info_cipher_kdf_alg_info(self, ctx):
        """Return cipher kdf alg info."""
        vscf_message_info_cipher_kdf_alg_info = self._lib.vscf_message_info_cipher_kdf_alg_info
        vscf_message_info_cipher_kdf_alg_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_cipher_kdf_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_message_info_cipher_kdf_alg_info(ctx)

    def vscf_message_info_has_cipher_padding_alg_info(self, ctx):
        """Return true if cipher padding alg info exists."""
        vscf_message_info_has_cipher_padding_alg_info = self._lib.vscf_message_info_has_cipher_padding_alg_info
        vscf_message_info_has_cipher_padding_alg_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_has_cipher_padding_alg_info.restype = c_bool
        return vscf_message_info_has_cipher_padding_alg_info(ctx)

    def vscf_message_info_cipher_padding_alg_info(self, ctx):
        """Return cipher padding alg info."""
        vscf_message_info_cipher_padding_alg_info = self._lib.vscf_message_info_cipher_padding_alg_info
        vscf_message_info_cipher_padding_alg_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_cipher_padding_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_message_info_cipher_padding_alg_info(ctx)

    def vscf_message_info_has_footer_info(self, ctx):
        """Return true if footer info exists."""
        vscf_message_info_has_footer_info = self._lib.vscf_message_info_has_footer_info
        vscf_message_info_has_footer_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_has_footer_info.restype = c_bool
        return vscf_message_info_has_footer_info(ctx)

    def vscf_message_info_footer_info(self, ctx):
        """Return footer info."""
        vscf_message_info_footer_info = self._lib.vscf_message_info_footer_info
        vscf_message_info_footer_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_footer_info.restype = POINTER(vscf_footer_info_t)
        return vscf_message_info_footer_info(ctx)

    def vscf_message_info_clear(self, ctx):
        """Remove all infos."""
        vscf_message_info_clear = self._lib.vscf_message_info_clear
        vscf_message_info_clear.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_clear.restype = None
        return vscf_message_info_clear(ctx)

    def vscf_message_info_shallow_copy(self, ctx):
        vscf_message_info_shallow_copy = self._lib.vscf_message_info_shallow_copy
        vscf_message_info_shallow_copy.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_shallow_copy.restype = POINTER(vscf_message_info_t)
        return vscf_message_info_shallow_copy(ctx)
