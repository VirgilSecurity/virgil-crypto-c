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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscf_impl import vscf_impl_t


class vscf_entropy_accumulator_t(Structure):
    pass


class VscfEntropyAccumulator(object):
    """Implementation based on a simple entropy accumulator."""

    SOURCES_MAX = 15

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_entropy_accumulator_new(self):
        vscf_entropy_accumulator_new = self._lib.vscf_entropy_accumulator_new
        vscf_entropy_accumulator_new.argtypes = []
        vscf_entropy_accumulator_new.restype = POINTER(vscf_entropy_accumulator_t)
        return vscf_entropy_accumulator_new()

    def vscf_entropy_accumulator_delete(self, ctx):
        vscf_entropy_accumulator_delete = self._lib.vscf_entropy_accumulator_delete
        vscf_entropy_accumulator_delete.argtypes = [POINTER(vscf_entropy_accumulator_t)]
        vscf_entropy_accumulator_delete.restype = None
        return vscf_entropy_accumulator_delete(ctx)

    def vscf_entropy_accumulator_is_strong(self, ctx):
        """Defines that implemented source is strong."""
        vscf_entropy_accumulator_is_strong = self._lib.vscf_entropy_accumulator_is_strong
        vscf_entropy_accumulator_is_strong.argtypes = [POINTER(vscf_entropy_accumulator_t)]
        vscf_entropy_accumulator_is_strong.restype = c_bool
        return vscf_entropy_accumulator_is_strong(ctx)

    def vscf_entropy_accumulator_gather(self, ctx, len, out):
        """Gather entropy of the requested length."""
        vscf_entropy_accumulator_gather = self._lib.vscf_entropy_accumulator_gather
        vscf_entropy_accumulator_gather.argtypes = [POINTER(vscf_entropy_accumulator_t), c_size_t, POINTER(vsc_buffer_t)]
        vscf_entropy_accumulator_gather.restype = c_int
        return vscf_entropy_accumulator_gather(ctx, len, out)

    def vscf_entropy_accumulator_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_entropy_accumulator_setup_defaults = self._lib.vscf_entropy_accumulator_setup_defaults
        vscf_entropy_accumulator_setup_defaults.argtypes = [POINTER(vscf_entropy_accumulator_t)]
        vscf_entropy_accumulator_setup_defaults.restype = None
        return vscf_entropy_accumulator_setup_defaults(ctx)

    def vscf_entropy_accumulator_add_source(self, ctx, source, threshold):
        """Add given entropy source to the accumulator.
        Threshold defines minimum number of bytes that must be gathered
        from the source during accumulation."""
        vscf_entropy_accumulator_add_source = self._lib.vscf_entropy_accumulator_add_source
        vscf_entropy_accumulator_add_source.argtypes = [POINTER(vscf_entropy_accumulator_t), POINTER(vscf_impl_t), c_size_t]
        vscf_entropy_accumulator_add_source.restype = None
        return vscf_entropy_accumulator_add_source(ctx, source, threshold)

    def vscf_entropy_accumulator_shallow_copy(self, ctx):
        vscf_entropy_accumulator_shallow_copy = self._lib.vscf_entropy_accumulator_shallow_copy
        vscf_entropy_accumulator_shallow_copy.argtypes = [POINTER(vscf_entropy_accumulator_t)]
        vscf_entropy_accumulator_shallow_copy.restype = POINTER(vscf_entropy_accumulator_t)
        return vscf_entropy_accumulator_shallow_copy(ctx)

    def vscf_entropy_accumulator_impl(self, ctx):
        vscf_entropy_accumulator_impl = self._lib.vscf_entropy_accumulator_impl
        vscf_entropy_accumulator_impl.argtypes = [POINTER(vscf_entropy_accumulator_t)]
        vscf_entropy_accumulator_impl.restype = POINTER(vscf_impl_t)
        return vscf_entropy_accumulator_impl(ctx)
