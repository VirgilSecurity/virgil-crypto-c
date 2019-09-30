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
from ._vscf_signed_data_info import vscf_signed_data_info_t


class vscf_footer_info_t(Structure):
    pass


class VscfFooterInfo(object):
    """Handle meta information about footer."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_footer_info_new(self):
        vscf_footer_info_new = self._lib.vscf_footer_info_new
        vscf_footer_info_new.argtypes = []
        vscf_footer_info_new.restype = POINTER(vscf_footer_info_t)
        return vscf_footer_info_new()

    def vscf_footer_info_delete(self, ctx):
        vscf_footer_info_delete = self._lib.vscf_footer_info_delete
        vscf_footer_info_delete.argtypes = [POINTER(vscf_footer_info_t)]
        vscf_footer_info_delete.restype = None
        return vscf_footer_info_delete(ctx)

    def vscf_footer_info_has_signed_data_info(self, ctx):
        """Retrun true if signed data info present."""
        vscf_footer_info_has_signed_data_info = self._lib.vscf_footer_info_has_signed_data_info
        vscf_footer_info_has_signed_data_info.argtypes = [POINTER(vscf_footer_info_t)]
        vscf_footer_info_has_signed_data_info.restype = c_bool
        return vscf_footer_info_has_signed_data_info(ctx)

    def vscf_footer_info_signed_data_info(self, ctx):
        """Return signed data info."""
        vscf_footer_info_signed_data_info = self._lib.vscf_footer_info_signed_data_info
        vscf_footer_info_signed_data_info.argtypes = [POINTER(vscf_footer_info_t)]
        vscf_footer_info_signed_data_info.restype = POINTER(vscf_signed_data_info_t)
        return vscf_footer_info_signed_data_info(ctx)

    def vscf_footer_info_set_data_size(self, ctx, data_size):
        """Set data size."""
        vscf_footer_info_set_data_size = self._lib.vscf_footer_info_set_data_size
        vscf_footer_info_set_data_size.argtypes = [POINTER(vscf_footer_info_t), c_size_t]
        vscf_footer_info_set_data_size.restype = None
        return vscf_footer_info_set_data_size(ctx, data_size)

    def vscf_footer_info_data_size(self, ctx):
        """Return data size."""
        vscf_footer_info_data_size = self._lib.vscf_footer_info_data_size
        vscf_footer_info_data_size.argtypes = [POINTER(vscf_footer_info_t)]
        vscf_footer_info_data_size.restype = c_size_t
        return vscf_footer_info_data_size(ctx)

    def vscf_footer_info_shallow_copy(self, ctx):
        vscf_footer_info_shallow_copy = self._lib.vscf_footer_info_shallow_copy
        vscf_footer_info_shallow_copy.argtypes = [POINTER(vscf_footer_info_t)]
        vscf_footer_info_shallow_copy.restype = POINTER(vscf_footer_info_t)
        return vscf_footer_info_shallow_copy(ctx)
