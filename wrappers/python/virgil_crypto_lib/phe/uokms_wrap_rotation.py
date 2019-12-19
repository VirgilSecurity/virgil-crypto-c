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
from ._c_bridge import VsceUokmsWrapRotation
from ._c_bridge import VsceStatus
from virgil_crypto_lib.common._c_bridge import Data
from .common import Common
from virgil_crypto_lib.common._c_bridge import Buffer


class UokmsWrapRotation(object):
    """Implements wrap rotation."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsce_uokms_wrap_rotation = VsceUokmsWrapRotation()
        self.ctx = self._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_delete(self.ctx)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        """Setups dependencies with default values."""
        status = self._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def set_update_token(self, update_token):
        """Sets update token. Should be called only once and before any other function"""
        d_update_token = Data(update_token)
        status = self._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_set_update_token(self.ctx, d_update_token.data)
        VsceStatus.handle_status(status)

    def update_wrap(self, wrap):
        """Updates EnrollmentRecord using server's update token"""
        d_wrap = Data(wrap)
        new_wrap = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_update_wrap(self.ctx, d_wrap.data, new_wrap.c_buffer)
        VsceStatus.handle_status(status)
        return new_wrap.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_uokms_wrap_rotation = VsceUokmsWrapRotation()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_uokms_wrap_rotation = VsceUokmsWrapRotation()
        inst.ctx = inst._lib_vsce_uokms_wrap_rotation.vsce_uokms_wrap_rotation_shallow_copy(c_ctx)
        return inst
