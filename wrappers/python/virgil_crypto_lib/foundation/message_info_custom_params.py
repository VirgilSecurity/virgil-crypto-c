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
from ._c_bridge import VscfMessageInfoCustomParams
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfStatus


class MessageInfoCustomParams(object):

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_message_info_custom_params = VscfMessageInfoCustomParams()
        self.ctx = self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_delete(self.ctx)

    def add_int(self, key, value):
        """Add custom parameter with integer value."""
        d_key = Data(key)
        self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_add_int(self.ctx, d_key.data, value)

    def add_string(self, key, value):
        """Add custom parameter with UTF8 string value."""
        d_key = Data(key)
        d_value = Data(value)
        self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_add_string(self.ctx, d_key.data, d_value.data)

    def add_data(self, key, value):
        """Add custom parameter with octet string value."""
        d_key = Data(key)
        d_value = Data(value)
        self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_add_data(self.ctx, d_key.data, d_value.data)

    def clear(self):
        """Remove all parameters."""
        self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_clear(self.ctx)

    def find_int(self, key):
        """Return custom parameter with integer value."""
        d_key = Data(key)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_find_int(self.ctx, d_key.data, error)
        VscfStatus.handle_status(error.status)
        return result

    def find_string(self, key):
        """Return custom parameter with UTF8 string value."""
        d_key = Data(key)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_find_string(self.ctx, d_key.data, error)
        VscfStatus.handle_status(error.status)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def find_data(self, key):
        """Return custom parameter with octet string value."""
        d_key = Data(key)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_find_data(self.ctx, d_key.data, error)
        VscfStatus.handle_status(error.status)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def has_params(self):
        """Return true if at least one param exists."""
        result = self._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_has_params(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_custom_params = VscfMessageInfoCustomParams()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_custom_params = VscfMessageInfoCustomParams()
        inst.ctx = inst._lib_vscf_message_info_custom_params.vscf_message_info_custom_params_shallow_copy(c_ctx)
        return inst
