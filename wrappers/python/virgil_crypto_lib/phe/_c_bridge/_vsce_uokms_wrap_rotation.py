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


class vsce_uokms_wrap_rotation_t(Structure):
    pass


class VsceUokmsWrapRotation(object):
    """Implements wrap rotation."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.phe

    def vsce_uokms_wrap_rotation_new(self):
        vsce_uokms_wrap_rotation_new = self._lib.vsce_uokms_wrap_rotation_new
        vsce_uokms_wrap_rotation_new.argtypes = []
        vsce_uokms_wrap_rotation_new.restype = POINTER(vsce_uokms_wrap_rotation_t)
        return vsce_uokms_wrap_rotation_new()

    def vsce_uokms_wrap_rotation_delete(self, ctx):
        vsce_uokms_wrap_rotation_delete = self._lib.vsce_uokms_wrap_rotation_delete
        vsce_uokms_wrap_rotation_delete.argtypes = [POINTER(vsce_uokms_wrap_rotation_t)]
        vsce_uokms_wrap_rotation_delete.restype = None
        return vsce_uokms_wrap_rotation_delete(ctx)

    def vsce_uokms_wrap_rotation_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vsce_uokms_wrap_rotation_use_operation_random = self._lib.vsce_uokms_wrap_rotation_use_operation_random
        vsce_uokms_wrap_rotation_use_operation_random.argtypes = [POINTER(vsce_uokms_wrap_rotation_t), POINTER(vscf_impl_t)]
        vsce_uokms_wrap_rotation_use_operation_random.restype = None
        return vsce_uokms_wrap_rotation_use_operation_random(ctx, operation_random)

    def vsce_uokms_wrap_rotation_setup_defaults(self, ctx):
        """Setups dependencies with default values."""
        vsce_uokms_wrap_rotation_setup_defaults = self._lib.vsce_uokms_wrap_rotation_setup_defaults
        vsce_uokms_wrap_rotation_setup_defaults.argtypes = [POINTER(vsce_uokms_wrap_rotation_t)]
        vsce_uokms_wrap_rotation_setup_defaults.restype = c_int
        return vsce_uokms_wrap_rotation_setup_defaults(ctx)

    def vsce_uokms_wrap_rotation_set_update_token(self, ctx, update_token):
        """Sets update token. Should be called only once and before any other function"""
        vsce_uokms_wrap_rotation_set_update_token = self._lib.vsce_uokms_wrap_rotation_set_update_token
        vsce_uokms_wrap_rotation_set_update_token.argtypes = [POINTER(vsce_uokms_wrap_rotation_t), vsc_data_t]
        vsce_uokms_wrap_rotation_set_update_token.restype = c_int
        return vsce_uokms_wrap_rotation_set_update_token(ctx, update_token)

    def vsce_uokms_wrap_rotation_update_wrap(self, ctx, wrap, new_wrap):
        """Updates EnrollmentRecord using server's update token"""
        vsce_uokms_wrap_rotation_update_wrap = self._lib.vsce_uokms_wrap_rotation_update_wrap
        vsce_uokms_wrap_rotation_update_wrap.argtypes = [POINTER(vsce_uokms_wrap_rotation_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_uokms_wrap_rotation_update_wrap.restype = c_int
        return vsce_uokms_wrap_rotation_update_wrap(ctx, wrap, new_wrap)

    def vsce_uokms_wrap_rotation_shallow_copy(self, ctx):
        vsce_uokms_wrap_rotation_shallow_copy = self._lib.vsce_uokms_wrap_rotation_shallow_copy
        vsce_uokms_wrap_rotation_shallow_copy.argtypes = [POINTER(vsce_uokms_wrap_rotation_t)]
        vsce_uokms_wrap_rotation_shallow_copy.restype = POINTER(vsce_uokms_wrap_rotation_t)
        return vsce_uokms_wrap_rotation_shallow_copy(ctx)
