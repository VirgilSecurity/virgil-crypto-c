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
from ._vscf_signer_info_list import vscf_signer_info_list_t
from ._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vscf_message_info_footer_t(Structure):
    pass


class VscfMessageInfoFooter(object):
    """Handle message signatures and related information."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_footer_new(self):
        vscf_message_info_footer_new = self._lib.vscf_message_info_footer_new
        vscf_message_info_footer_new.argtypes = []
        vscf_message_info_footer_new.restype = POINTER(vscf_message_info_footer_t)
        return vscf_message_info_footer_new()

    def vscf_message_info_footer_delete(self, ctx):
        vscf_message_info_footer_delete = self._lib.vscf_message_info_footer_delete
        vscf_message_info_footer_delete.argtypes = [POINTER(vscf_message_info_footer_t)]
        vscf_message_info_footer_delete.restype = None
        return vscf_message_info_footer_delete(ctx)

    def vscf_message_info_footer_has_signer_infos(self, ctx):
        """Return true if at least one signer info presents."""
        vscf_message_info_footer_has_signer_infos = self._lib.vscf_message_info_footer_has_signer_infos
        vscf_message_info_footer_has_signer_infos.argtypes = [POINTER(vscf_message_info_footer_t)]
        vscf_message_info_footer_has_signer_infos.restype = c_bool
        return vscf_message_info_footer_has_signer_infos(ctx)

    def vscf_message_info_footer_signer_infos(self, ctx):
        """Return list with a "signer info" elements."""
        vscf_message_info_footer_signer_infos = self._lib.vscf_message_info_footer_signer_infos
        vscf_message_info_footer_signer_infos.argtypes = [POINTER(vscf_message_info_footer_t)]
        vscf_message_info_footer_signer_infos.restype = POINTER(vscf_signer_info_list_t)
        return vscf_message_info_footer_signer_infos(ctx)

    def vscf_message_info_footer_signer_hash_alg_info(self, ctx):
        """Return information about algorithm that was used for data hashing."""
        vscf_message_info_footer_signer_hash_alg_info = self._lib.vscf_message_info_footer_signer_hash_alg_info
        vscf_message_info_footer_signer_hash_alg_info.argtypes = [POINTER(vscf_message_info_footer_t)]
        vscf_message_info_footer_signer_hash_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_message_info_footer_signer_hash_alg_info(ctx)

    def vscf_message_info_footer_signer_digest(self, ctx):
        """Return plain text digest that was used to produce signature."""
        vscf_message_info_footer_signer_digest = self._lib.vscf_message_info_footer_signer_digest
        vscf_message_info_footer_signer_digest.argtypes = [POINTER(vscf_message_info_footer_t)]
        vscf_message_info_footer_signer_digest.restype = vsc_data_t
        return vscf_message_info_footer_signer_digest(ctx)

    def vscf_message_info_footer_shallow_copy(self, ctx):
        vscf_message_info_footer_shallow_copy = self._lib.vscf_message_info_footer_shallow_copy
        vscf_message_info_footer_shallow_copy.argtypes = [POINTER(vscf_message_info_footer_t)]
        vscf_message_info_footer_shallow_copy.restype = POINTER(vscf_message_info_footer_t)
        return vscf_message_info_footer_shallow_copy(ctx)
