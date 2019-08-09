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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_impl import vscf_impl_t


class vscf_key_recipient_info_t(Structure):
    pass


class VscfKeyRecipientInfo(object):
    """Handle information about recipient that is defined by a Public Key."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_key_recipient_info_new(self):
        vscf_key_recipient_info_new = self._lib.vscf_key_recipient_info_new
        vscf_key_recipient_info_new.argtypes = []
        vscf_key_recipient_info_new.restype = POINTER(vscf_key_recipient_info_t)
        return vscf_key_recipient_info_new()

    def vscf_key_recipient_info_delete(self, ctx):
        vscf_key_recipient_info_delete = self._lib.vscf_key_recipient_info_delete
        vscf_key_recipient_info_delete.argtypes = [POINTER(vscf_key_recipient_info_t)]
        vscf_key_recipient_info_delete.restype = None
        return vscf_key_recipient_info_delete(ctx)

    def vscf_key_recipient_info_new_with_data(self, recipient_id, key_encryption_algorithm, encrypted_key):
        """Create object and define all properties."""
        vscf_key_recipient_info_new_with_data = self._lib.vscf_key_recipient_info_new_with_data
        vscf_key_recipient_info_new_with_data.argtypes = [vsc_data_t, POINTER(vscf_impl_t), vsc_data_t]
        vscf_key_recipient_info_new_with_data.restype = POINTER(vscf_key_recipient_info_t)
        return vscf_key_recipient_info_new_with_data(recipient_id, key_encryption_algorithm, encrypted_key)

    def vscf_key_recipient_info_recipient_id(self, ctx):
        """Return recipient identifier."""
        vscf_key_recipient_info_recipient_id = self._lib.vscf_key_recipient_info_recipient_id
        vscf_key_recipient_info_recipient_id.argtypes = [POINTER(vscf_key_recipient_info_t)]
        vscf_key_recipient_info_recipient_id.restype = vsc_data_t
        return vscf_key_recipient_info_recipient_id(ctx)

    def vscf_key_recipient_info_key_encryption_algorithm(self, ctx):
        """Return algorithm information that was used for encryption
        a data encryption key."""
        vscf_key_recipient_info_key_encryption_algorithm = self._lib.vscf_key_recipient_info_key_encryption_algorithm
        vscf_key_recipient_info_key_encryption_algorithm.argtypes = [POINTER(vscf_key_recipient_info_t)]
        vscf_key_recipient_info_key_encryption_algorithm.restype = POINTER(vscf_impl_t)
        return vscf_key_recipient_info_key_encryption_algorithm(ctx)

    def vscf_key_recipient_info_encrypted_key(self, ctx):
        """Return an encrypted data encryption key."""
        vscf_key_recipient_info_encrypted_key = self._lib.vscf_key_recipient_info_encrypted_key
        vscf_key_recipient_info_encrypted_key.argtypes = [POINTER(vscf_key_recipient_info_t)]
        vscf_key_recipient_info_encrypted_key.restype = vsc_data_t
        return vscf_key_recipient_info_encrypted_key(ctx)

    def vscf_key_recipient_info_shallow_copy(self, ctx):
        vscf_key_recipient_info_shallow_copy = self._lib.vscf_key_recipient_info_shallow_copy
        vscf_key_recipient_info_shallow_copy.argtypes = [POINTER(vscf_key_recipient_info_t)]
        vscf_key_recipient_info_shallow_copy.restype = POINTER(vscf_key_recipient_info_t)
        return vscf_key_recipient_info_shallow_copy(ctx)
