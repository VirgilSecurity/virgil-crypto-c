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
from ._vscf_impl import vscf_impl_t
from ._vscf_padding_params import vscf_padding_params_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_random_padding_t(Structure):
    pass


class VscfRandomPadding(object):
    """Append a random number of padding bytes to a data."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_random_padding_new(self):
        vscf_random_padding_new = self._lib.vscf_random_padding_new
        vscf_random_padding_new.argtypes = []
        vscf_random_padding_new.restype = POINTER(vscf_random_padding_t)
        return vscf_random_padding_new()

    def vscf_random_padding_delete(self, ctx):
        vscf_random_padding_delete = self._lib.vscf_random_padding_delete
        vscf_random_padding_delete.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_delete.restype = None
        return vscf_random_padding_delete(ctx)

    def vscf_random_padding_use_random(self, ctx, random):
        vscf_random_padding_use_random = self._lib.vscf_random_padding_use_random
        vscf_random_padding_use_random.argtypes = [POINTER(vscf_random_padding_t), POINTER(vscf_impl_t)]
        vscf_random_padding_use_random.restype = None
        return vscf_random_padding_use_random(ctx, random)

    def vscf_random_padding_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_random_padding_alg_id = self._lib.vscf_random_padding_alg_id
        vscf_random_padding_alg_id.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_alg_id.restype = c_int
        return vscf_random_padding_alg_id(ctx)

    def vscf_random_padding_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_random_padding_produce_alg_info = self._lib.vscf_random_padding_produce_alg_info
        vscf_random_padding_produce_alg_info.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_random_padding_produce_alg_info(ctx)

    def vscf_random_padding_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_random_padding_restore_alg_info = self._lib.vscf_random_padding_restore_alg_info
        vscf_random_padding_restore_alg_info.argtypes = [POINTER(vscf_random_padding_t), POINTER(vscf_impl_t)]
        vscf_random_padding_restore_alg_info.restype = c_int
        return vscf_random_padding_restore_alg_info(ctx, alg_info)

    def vscf_random_padding_configure(self, ctx, params):
        """Set new padding parameters."""
        vscf_random_padding_configure = self._lib.vscf_random_padding_configure
        vscf_random_padding_configure.argtypes = [POINTER(vscf_random_padding_t), POINTER(vscf_padding_params_t)]
        vscf_random_padding_configure.restype = None
        return vscf_random_padding_configure(ctx, params)

    def vscf_random_padding_padded_data_len(self, ctx, data_len):
        """Return length in bytes of a data with a padding."""
        vscf_random_padding_padded_data_len = self._lib.vscf_random_padding_padded_data_len
        vscf_random_padding_padded_data_len.argtypes = [POINTER(vscf_random_padding_t), c_size_t]
        vscf_random_padding_padded_data_len.restype = c_size_t
        return vscf_random_padding_padded_data_len(ctx, data_len)

    def vscf_random_padding_len(self, ctx):
        """Return an actual number of padding in bytes.
        Note, this method might be called right before "finish data processing"."""
        vscf_random_padding_len = self._lib.vscf_random_padding_len
        vscf_random_padding_len.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_len.restype = c_size_t
        return vscf_random_padding_len(ctx)

    def vscf_random_padding_len_max(self, ctx):
        """Return a maximum number of padding in bytes."""
        vscf_random_padding_len_max = self._lib.vscf_random_padding_len_max
        vscf_random_padding_len_max.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_len_max.restype = c_size_t
        return vscf_random_padding_len_max(ctx)

    def vscf_random_padding_start_data_processing(self, ctx):
        """Prepare the algorithm to process data."""
        vscf_random_padding_start_data_processing = self._lib.vscf_random_padding_start_data_processing
        vscf_random_padding_start_data_processing.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_start_data_processing.restype = None
        return vscf_random_padding_start_data_processing(ctx)

    def vscf_random_padding_process_data(self, ctx, data):
        """Only data length is needed to produce padding later.
        Return data that should be further proceeded."""
        vscf_random_padding_process_data = self._lib.vscf_random_padding_process_data
        vscf_random_padding_process_data.argtypes = [POINTER(vscf_random_padding_t), vsc_data_t]
        vscf_random_padding_process_data.restype = vsc_data_t
        return vscf_random_padding_process_data(ctx, data)

    def vscf_random_padding_finish_data_processing(self, ctx, out):
        """Accomplish data processing and return padding."""
        vscf_random_padding_finish_data_processing = self._lib.vscf_random_padding_finish_data_processing
        vscf_random_padding_finish_data_processing.argtypes = [POINTER(vscf_random_padding_t), POINTER(vsc_buffer_t)]
        vscf_random_padding_finish_data_processing.restype = c_int
        return vscf_random_padding_finish_data_processing(ctx, out)

    def vscf_random_padding_start_padded_data_processing(self, ctx):
        """Prepare the algorithm to process padded data."""
        vscf_random_padding_start_padded_data_processing = self._lib.vscf_random_padding_start_padded_data_processing
        vscf_random_padding_start_padded_data_processing.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_start_padded_data_processing.restype = None
        return vscf_random_padding_start_padded_data_processing(ctx)

    def vscf_random_padding_process_padded_data(self, ctx, data, out):
        """Process padded data.
        Return filtered data without padding."""
        vscf_random_padding_process_padded_data = self._lib.vscf_random_padding_process_padded_data
        vscf_random_padding_process_padded_data.argtypes = [POINTER(vscf_random_padding_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_random_padding_process_padded_data.restype = None
        return vscf_random_padding_process_padded_data(ctx, data, out)

    def vscf_random_padding_finish_padded_data_processing_out_len(self, ctx):
        """Return length in bytes required hold output of the method
        "finish padded data processing"."""
        vscf_random_padding_finish_padded_data_processing_out_len = self._lib.vscf_random_padding_finish_padded_data_processing_out_len
        vscf_random_padding_finish_padded_data_processing_out_len.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_finish_padded_data_processing_out_len.restype = c_size_t
        return vscf_random_padding_finish_padded_data_processing_out_len(ctx)

    def vscf_random_padding_finish_padded_data_processing(self, ctx, out):
        """Accomplish padded data processing and return left data without a padding."""
        vscf_random_padding_finish_padded_data_processing = self._lib.vscf_random_padding_finish_padded_data_processing
        vscf_random_padding_finish_padded_data_processing.argtypes = [POINTER(vscf_random_padding_t), POINTER(vsc_buffer_t)]
        vscf_random_padding_finish_padded_data_processing.restype = c_int
        return vscf_random_padding_finish_padded_data_processing(ctx, out)

    def vscf_random_padding_shallow_copy(self, ctx):
        vscf_random_padding_shallow_copy = self._lib.vscf_random_padding_shallow_copy
        vscf_random_padding_shallow_copy.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_shallow_copy.restype = POINTER(vscf_random_padding_t)
        return vscf_random_padding_shallow_copy(ctx)

    def vscf_random_padding_impl(self, ctx):
        vscf_random_padding_impl = self._lib.vscf_random_padding_impl
        vscf_random_padding_impl.argtypes = [POINTER(vscf_random_padding_t)]
        vscf_random_padding_impl.restype = POINTER(vscf_impl_t)
        return vscf_random_padding_impl(ctx)
