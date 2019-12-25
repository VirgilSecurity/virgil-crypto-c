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


class vscf_padding_params_t(Structure):
    pass


class VscfPaddingParams(object):
    """Handles padding parameters and constraints."""

    DEFAULT_FRAME_MIN = 32
    DEFAULT_FRAME = 160
    DEFAULT_FRAME_MAX = 256

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_padding_params_new(self):
        vscf_padding_params_new = self._lib.vscf_padding_params_new
        vscf_padding_params_new.argtypes = []
        vscf_padding_params_new.restype = POINTER(vscf_padding_params_t)
        return vscf_padding_params_new()

    def vscf_padding_params_delete(self, ctx):
        vscf_padding_params_delete = self._lib.vscf_padding_params_delete
        vscf_padding_params_delete.argtypes = [POINTER(vscf_padding_params_t)]
        vscf_padding_params_delete.restype = None
        return vscf_padding_params_delete(ctx)

    def vscf_padding_params_new_with_constraints(self, frame, frame_max):
        """Build padding params with given constraints.
        Next formula can clarify what frame is: padding_length = data_length MOD frame"""
        vscf_padding_params_new_with_constraints = self._lib.vscf_padding_params_new_with_constraints
        vscf_padding_params_new_with_constraints.argtypes = [c_size_t, c_size_t]
        vscf_padding_params_new_with_constraints.restype = POINTER(vscf_padding_params_t)
        return vscf_padding_params_new_with_constraints(frame, frame_max)

    def vscf_padding_params_frame(self, ctx):
        """Return padding frame in bytes."""
        vscf_padding_params_frame = self._lib.vscf_padding_params_frame
        vscf_padding_params_frame.argtypes = [POINTER(vscf_padding_params_t)]
        vscf_padding_params_frame.restype = c_size_t
        return vscf_padding_params_frame(ctx)

    def vscf_padding_params_frame_max(self, ctx):
        """Return maximum padding frame in bytes."""
        vscf_padding_params_frame_max = self._lib.vscf_padding_params_frame_max
        vscf_padding_params_frame_max.argtypes = [POINTER(vscf_padding_params_t)]
        vscf_padding_params_frame_max.restype = c_size_t
        return vscf_padding_params_frame_max(ctx)

    def vscf_padding_params_shallow_copy(self, ctx):
        vscf_padding_params_shallow_copy = self._lib.vscf_padding_params_shallow_copy
        vscf_padding_params_shallow_copy.argtypes = [POINTER(vscf_padding_params_t)]
        vscf_padding_params_shallow_copy.restype = POINTER(vscf_padding_params_t)
        return vscf_padding_params_shallow_copy(ctx)
