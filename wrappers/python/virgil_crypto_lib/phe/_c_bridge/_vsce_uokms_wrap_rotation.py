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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vsce_uokms_wrap_rotation_t(Structure):
    pass


class VsceUokmsWrapRotation(object):

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

    def vsce_uokms_wrap_rotation_update_wrap(self, ctx, wrap, update_token, new_wrap):
        """Updates EnrollmentRecord using server's update token"""
        vsce_uokms_wrap_rotation_update_wrap = self._lib.vsce_uokms_wrap_rotation_update_wrap
        vsce_uokms_wrap_rotation_update_wrap.argtypes = [POINTER(vsce_uokms_wrap_rotation_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_uokms_wrap_rotation_update_wrap.restype = c_int
        return vsce_uokms_wrap_rotation_update_wrap(ctx, wrap, update_token, new_wrap)

    def vsce_uokms_wrap_rotation_shallow_copy(self, ctx):
        vsce_uokms_wrap_rotation_shallow_copy = self._lib.vsce_uokms_wrap_rotation_shallow_copy
        vsce_uokms_wrap_rotation_shallow_copy.argtypes = [POINTER(vsce_uokms_wrap_rotation_t)]
        vsce_uokms_wrap_rotation_shallow_copy.restype = POINTER(vsce_uokms_wrap_rotation_t)
        return vsce_uokms_wrap_rotation_shallow_copy(ctx)
