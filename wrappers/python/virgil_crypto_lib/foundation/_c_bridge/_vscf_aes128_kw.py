# Copyright (C) 2015-2026 Virgil Security, Inc.
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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_aes128_kw_t(Structure):
    pass


class VscfAes128Kw(object):
    """Implementation of AES-128 Key Wrap algorithm (RFC 3394)."""


    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_aes128_kw_new(self):
        vscf_aes128_kw_new = self._lib.vscf_aes128_kw_new
        vscf_aes128_kw_new.argtypes = []
        vscf_aes128_kw_new.restype = POINTER(vscf_aes128_kw_t)
        return vscf_aes128_kw_new()

    def vscf_aes128_kw_delete(self, ctx):
        vscf_aes128_kw_delete = self._lib.vscf_aes128_kw_delete
        vscf_aes128_kw_delete.argtypes = [POINTER(vscf_aes128_kw_t)]
        vscf_aes128_kw_delete.restype = None
        return vscf_aes128_kw_delete(ctx)

    def vscf_aes128_kw_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_aes128_kw_alg_id = self._lib.vscf_aes128_kw_alg_id
        vscf_aes128_kw_alg_id.argtypes = [POINTER(vscf_aes128_kw_t)]
        vscf_aes128_kw_alg_id.restype = c_int
        return vscf_aes128_kw_alg_id(ctx)

    def vscf_aes128_kw_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_aes128_kw_produce_alg_info = self._lib.vscf_aes128_kw_produce_alg_info
        vscf_aes128_kw_produce_alg_info.argtypes = [POINTER(vscf_aes128_kw_t)]
        vscf_aes128_kw_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_aes128_kw_produce_alg_info(ctx)

    def vscf_aes128_kw_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_aes128_kw_restore_alg_info = self._lib.vscf_aes128_kw_restore_alg_info
        vscf_aes128_kw_restore_alg_info.argtypes = [POINTER(vscf_aes128_kw_t), POINTER(vscf_impl_t)]
        vscf_aes128_kw_restore_alg_info.restype = c_int
        return vscf_aes128_kw_restore_alg_info(ctx, alg_info)

    def vscf_aes128_kw_wrapped_len(self, ctx, data_len):
        """Return buffer length required to hold a wrapped key for the given plain key length."""
        vscf_aes128_kw_wrapped_len = self._lib.vscf_aes128_kw_wrapped_len
        vscf_aes128_kw_wrapped_len.argtypes = [POINTER(vscf_aes128_kw_t), c_size_t]
        vscf_aes128_kw_wrapped_len.restype = c_size_t
        return vscf_aes128_kw_wrapped_len(ctx, data_len)

    def vscf_aes128_kw_unwrapped_len(self, ctx, data_len):
        """Return buffer length required to hold an unwrapped key for the given wrapped key length."""
        vscf_aes128_kw_unwrapped_len = self._lib.vscf_aes128_kw_unwrapped_len
        vscf_aes128_kw_unwrapped_len.argtypes = [POINTER(vscf_aes128_kw_t), c_size_t]
        vscf_aes128_kw_unwrapped_len.restype = c_size_t
        return vscf_aes128_kw_unwrapped_len(ctx, data_len)

    def vscf_aes128_kw_wrap(self, ctx, kek, data, out):
        """Wrap given key data using the Key Encryption Key (KEK)."""
        vscf_aes128_kw_wrap = self._lib.vscf_aes128_kw_wrap
        vscf_aes128_kw_wrap.argtypes = [POINTER(vscf_aes128_kw_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_aes128_kw_wrap.restype = c_int
        return vscf_aes128_kw_wrap(ctx, kek, data, out)

    def vscf_aes128_kw_unwrap(self, ctx, kek, data, out):
        """Unwrap given key data using the Key Encryption Key (KEK)."""
        vscf_aes128_kw_unwrap = self._lib.vscf_aes128_kw_unwrap
        vscf_aes128_kw_unwrap.argtypes = [POINTER(vscf_aes128_kw_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_aes128_kw_unwrap.restype = c_int
        return vscf_aes128_kw_unwrap(ctx, kek, data, out)

    def vscf_aes128_kw_shallow_copy(self, ctx):
        vscf_aes128_kw_shallow_copy = self._lib.vscf_aes128_kw_shallow_copy
        vscf_aes128_kw_shallow_copy.argtypes = [POINTER(vscf_aes128_kw_t)]
        vscf_aes128_kw_shallow_copy.restype = POINTER(vscf_aes128_kw_t)
        return vscf_aes128_kw_shallow_copy(ctx)

    def vscf_aes128_kw_impl(self, ctx):
        vscf_aes128_kw_impl = self._lib.vscf_aes128_kw_impl
        vscf_aes128_kw_impl.argtypes = [POINTER(vscf_aes128_kw_t)]
        vscf_aes128_kw_impl.restype = POINTER(vscf_impl_t)
        return vscf_aes128_kw_impl(ctx)
