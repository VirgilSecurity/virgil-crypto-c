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
from ._vscf_error import vscf_error_t


class vscf_message_info_custom_params_t(Structure):
    pass


class VscfMessageInfoCustomParams(object):

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_custom_params_new(self):
        vscf_message_info_custom_params_new = self._lib.vscf_message_info_custom_params_new
        vscf_message_info_custom_params_new.argtypes = []
        vscf_message_info_custom_params_new.restype = POINTER(vscf_message_info_custom_params_t)
        return vscf_message_info_custom_params_new()

    def vscf_message_info_custom_params_delete(self, ctx):
        vscf_message_info_custom_params_delete = self._lib.vscf_message_info_custom_params_delete
        vscf_message_info_custom_params_delete.argtypes = [POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_custom_params_delete.restype = None
        return vscf_message_info_custom_params_delete(ctx)

    def vscf_message_info_custom_params_add_int(self, ctx, key, value):
        """Add custom parameter with integer value."""
        vscf_message_info_custom_params_add_int = self._lib.vscf_message_info_custom_params_add_int
        vscf_message_info_custom_params_add_int.argtypes = [POINTER(vscf_message_info_custom_params_t), vsc_data_t, c_int]
        vscf_message_info_custom_params_add_int.restype = None
        return vscf_message_info_custom_params_add_int(ctx, key, value)

    def vscf_message_info_custom_params_add_string(self, ctx, key, value):
        """Add custom parameter with UTF8 string value."""
        vscf_message_info_custom_params_add_string = self._lib.vscf_message_info_custom_params_add_string
        vscf_message_info_custom_params_add_string.argtypes = [POINTER(vscf_message_info_custom_params_t), vsc_data_t, vsc_data_t]
        vscf_message_info_custom_params_add_string.restype = None
        return vscf_message_info_custom_params_add_string(ctx, key, value)

    def vscf_message_info_custom_params_add_data(self, ctx, key, value):
        """Add custom parameter with octet string value."""
        vscf_message_info_custom_params_add_data = self._lib.vscf_message_info_custom_params_add_data
        vscf_message_info_custom_params_add_data.argtypes = [POINTER(vscf_message_info_custom_params_t), vsc_data_t, vsc_data_t]
        vscf_message_info_custom_params_add_data.restype = None
        return vscf_message_info_custom_params_add_data(ctx, key, value)

    def vscf_message_info_custom_params_clear(self, ctx):
        """Remove all parameters."""
        vscf_message_info_custom_params_clear = self._lib.vscf_message_info_custom_params_clear
        vscf_message_info_custom_params_clear.argtypes = [POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_custom_params_clear.restype = None
        return vscf_message_info_custom_params_clear(ctx)

    def vscf_message_info_custom_params_find_int(self, ctx, key, error):
        """Return custom parameter with integer value."""
        vscf_message_info_custom_params_find_int = self._lib.vscf_message_info_custom_params_find_int
        vscf_message_info_custom_params_find_int.argtypes = [POINTER(vscf_message_info_custom_params_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_custom_params_find_int.restype = c_int
        return vscf_message_info_custom_params_find_int(ctx, key, error)

    def vscf_message_info_custom_params_find_string(self, ctx, key, error):
        """Return custom parameter with UTF8 string value."""
        vscf_message_info_custom_params_find_string = self._lib.vscf_message_info_custom_params_find_string
        vscf_message_info_custom_params_find_string.argtypes = [POINTER(vscf_message_info_custom_params_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_custom_params_find_string.restype = vsc_data_t
        return vscf_message_info_custom_params_find_string(ctx, key, error)

    def vscf_message_info_custom_params_find_data(self, ctx, key, error):
        """Return custom parameter with octet string value."""
        vscf_message_info_custom_params_find_data = self._lib.vscf_message_info_custom_params_find_data
        vscf_message_info_custom_params_find_data.argtypes = [POINTER(vscf_message_info_custom_params_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_custom_params_find_data.restype = vsc_data_t
        return vscf_message_info_custom_params_find_data(ctx, key, error)

    def vscf_message_info_custom_params_has_params(self, ctx):
        """Return true if at least one param exists."""
        vscf_message_info_custom_params_has_params = self._lib.vscf_message_info_custom_params_has_params
        vscf_message_info_custom_params_has_params.argtypes = [POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_custom_params_has_params.restype = c_bool
        return vscf_message_info_custom_params_has_params(ctx)

    def vscf_message_info_custom_params_shallow_copy(self, ctx):
        vscf_message_info_custom_params_shallow_copy = self._lib.vscf_message_info_custom_params_shallow_copy
        vscf_message_info_custom_params_shallow_copy.argtypes = [POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_custom_params_shallow_copy.restype = POINTER(vscf_message_info_custom_params_t)
        return vscf_message_info_custom_params_shallow_copy(ctx)
