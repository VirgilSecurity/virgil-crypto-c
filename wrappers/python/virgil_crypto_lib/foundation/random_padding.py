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
from ._c_bridge import VscfRandomPadding
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from .alg import Alg
from .padding import Padding


class RandomPadding(Alg, Padding):
    """Append a random number of padding bytes to a data."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_random_padding = VscfRandomPadding()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_random_padding.vscf_random_padding_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_random_padding.vscf_random_padding_delete(self.ctx)

    def __len__(self):
        """Return an actual number of padding in bytes.
        Note, this method might be called right before "finish data processing"."""
        result = self._lib_vscf_random_padding.vscf_random_padding_len(self.ctx)
        return result

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_random_padding.vscf_random_padding_alg_id(self.ctx)
        return result

    def produce_alg_info(self):
        """Produce object with algorithm information and configuration parameters."""
        result = self._lib_vscf_random_padding.vscf_random_padding_produce_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def restore_alg_info(self, alg_info):
        """Restore algorithm configuration from the given object."""
        status = self._lib_vscf_random_padding.vscf_random_padding_restore_alg_info(self.ctx, alg_info.c_impl)
        VscfStatus.handle_status(status)

    def configure(self, params):
        """Set new padding parameters."""
        self._lib_vscf_random_padding.vscf_random_padding_configure(self.ctx, params.ctx)

    def padded_data_len(self, data_len):
        """Return length in bytes of a data with a padding."""
        result = self._lib_vscf_random_padding.vscf_random_padding_padded_data_len(self.ctx, data_len)
        return result

    def set_random(self, random):
        self._lib_vscf_random_padding.vscf_random_padding_use_random(self.ctx, random.c_impl)

    def len_max(self):
        """Return a maximum number of padding in bytes."""
        result = self._lib_vscf_random_padding.vscf_random_padding_len_max(self.ctx)
        return result

    def start_data_processing(self):
        """Prepare the algorithm to process data."""
        self._lib_vscf_random_padding.vscf_random_padding_start_data_processing(self.ctx)

    def process_data(self, data):
        """Only data length is needed to produce padding later.
        Return data that should be further proceeded."""
        d_data = Data(data)
        result = self._lib_vscf_random_padding.vscf_random_padding_process_data(self.ctx, d_data.data)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def finish_data_processing(self):
        """Accomplish data processing and return padding."""
        out = Buffer(self.len())
        status = self._lib_vscf_random_padding.vscf_random_padding_finish_data_processing(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def start_padded_data_processing(self):
        """Prepare the algorithm to process padded data."""
        self._lib_vscf_random_padding.vscf_random_padding_start_padded_data_processing(self.ctx)

    def process_padded_data(self, data):
        """Process padded data.
        Return filtered data without padding."""
        d_data = Data(data)
        out = Buffer(len(data))
        self._lib_vscf_random_padding.vscf_random_padding_process_padded_data(self.ctx, d_data.data, out.c_buffer)
        return out.get_bytes()

    def finish_padded_data_processing_out_len(self):
        """Return length in bytes required hold output of the method
        "finish padded data processing"."""
        result = self._lib_vscf_random_padding.vscf_random_padding_finish_padded_data_processing_out_len(self.ctx)
        return result

    def finish_padded_data_processing(self):
        """Accomplish padded data processing and return left data without a padding."""
        out = Buffer(self.finish_padded_data_processing_out_len())
        status = self._lib_vscf_random_padding.vscf_random_padding_finish_padded_data_processing(self.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_random_padding = VscfRandomPadding()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_random_padding = VscfRandomPadding()
        inst.ctx = inst._lib_vscf_random_padding.vscf_random_padding_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_random_padding.vscf_random_padding_shallow_copy(value)
        self._c_impl = self._lib_vscf_random_padding.vscf_random_padding_impl(self.ctx)
