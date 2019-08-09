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
from ._c_bridge import VscfEntropyAccumulator
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus
from .entropy_source import EntropySource


class EntropyAccumulator(EntropySource):
    """Implementation based on a simple entropy accumulator."""

    SOURCES_MAX = 15

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_entropy_accumulator = VscfEntropyAccumulator()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_delete(self.ctx)

    def is_strong(self):
        """Defines that implemented source is strong."""
        result = self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_is_strong(self.ctx)
        return result

    def gather(self, len):
        """Gather entropy of the requested length."""
        out = Buffer(len)
        status = self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_gather(self.ctx, len, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_setup_defaults(self.ctx)

    def add_source(self, source, threshold):
        """Add given entropy source to the accumulator.
        Threshold defines minimum number of bytes that must be gathered
        from the source during accumulation."""
        self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_add_source(self.ctx, source.c_impl, threshold)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_entropy_accumulator = VscfEntropyAccumulator()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_entropy_accumulator = VscfEntropyAccumulator()
        inst.ctx = inst._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_shallow_copy(value)
        self._c_impl = self._lib_vscf_entropy_accumulator.vscf_entropy_accumulator_impl(self.ctx)
