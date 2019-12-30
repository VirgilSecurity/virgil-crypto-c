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
from ._c_bridge import VscfPaddingParams


class PaddingParams(object):
    """Handles padding parameters and constraints."""

    DEFAULT_FRAME_MIN = 32
    DEFAULT_FRAME = 160
    DEFAULT_FRAME_MAX = 256

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_padding_params = VscfPaddingParams()
        self.ctx = self._lib_vscf_padding_params.vscf_padding_params_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_padding_params.vscf_padding_params_delete(self.ctx)

    @classmethod
    def with_constraints(cls, frame, frame_max):
        """Build padding params with given constraints.
        Next formula can clarify what frame is: padding_length = data_length MOD frame"""
        inst = cls.__new__(cls)
        inst._lib_vscf_padding_params = VscfPaddingParams()
        inst.ctx = inst._lib_vscf_padding_params.vscf_padding_params_new_with_constraints(frame, frame_max)
        return inst

    def frame(self):
        """Return padding frame in bytes."""
        result = self._lib_vscf_padding_params.vscf_padding_params_frame(self.ctx)
        return result

    def frame_max(self):
        """Return maximum padding frame in bytes."""
        result = self._lib_vscf_padding_params.vscf_padding_params_frame_max(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_padding_params = VscfPaddingParams()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_padding_params = VscfPaddingParams()
        inst.ctx = inst._lib_vscf_padding_params.vscf_padding_params_shallow_copy(c_ctx)
        return inst
