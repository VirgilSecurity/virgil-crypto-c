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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_alg_info_der_serializer_t(Structure):
    pass


class VscfAlgInfoDerSerializer(object):
    """Provide DER serializer of algorithm information."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_alg_info_der_serializer_new(self):
        vscf_alg_info_der_serializer_new = self._lib.vscf_alg_info_der_serializer_new
        vscf_alg_info_der_serializer_new.argtypes = []
        vscf_alg_info_der_serializer_new.restype = POINTER(vscf_alg_info_der_serializer_t)
        return vscf_alg_info_der_serializer_new()

    def vscf_alg_info_der_serializer_delete(self, ctx):
        vscf_alg_info_der_serializer_delete = self._lib.vscf_alg_info_der_serializer_delete
        vscf_alg_info_der_serializer_delete.argtypes = [POINTER(vscf_alg_info_der_serializer_t)]
        vscf_alg_info_der_serializer_delete.restype = None
        return vscf_alg_info_der_serializer_delete(ctx)

    def vscf_alg_info_der_serializer_use_asn1_writer(self, ctx, asn1_writer):
        vscf_alg_info_der_serializer_use_asn1_writer = self._lib.vscf_alg_info_der_serializer_use_asn1_writer
        vscf_alg_info_der_serializer_use_asn1_writer.argtypes = [POINTER(vscf_alg_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_alg_info_der_serializer_use_asn1_writer.restype = None
        return vscf_alg_info_der_serializer_use_asn1_writer(ctx, asn1_writer)

    def vscf_alg_info_der_serializer_serialized_len(self, ctx, alg_info):
        """Return buffer size enough to hold serialized algorithm."""
        vscf_alg_info_der_serializer_serialized_len = self._lib.vscf_alg_info_der_serializer_serialized_len
        vscf_alg_info_der_serializer_serialized_len.argtypes = [POINTER(vscf_alg_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_alg_info_der_serializer_serialized_len.restype = c_size_t
        return vscf_alg_info_der_serializer_serialized_len(ctx, alg_info)

    def vscf_alg_info_der_serializer_serialize(self, ctx, alg_info, out):
        """Serialize algorithm info to buffer class."""
        vscf_alg_info_der_serializer_serialize = self._lib.vscf_alg_info_der_serializer_serialize
        vscf_alg_info_der_serializer_serialize.argtypes = [POINTER(vscf_alg_info_der_serializer_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_alg_info_der_serializer_serialize.restype = None
        return vscf_alg_info_der_serializer_serialize(ctx, alg_info, out)

    def vscf_alg_info_der_serializer_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_alg_info_der_serializer_setup_defaults = self._lib.vscf_alg_info_der_serializer_setup_defaults
        vscf_alg_info_der_serializer_setup_defaults.argtypes = [POINTER(vscf_alg_info_der_serializer_t)]
        vscf_alg_info_der_serializer_setup_defaults.restype = None
        return vscf_alg_info_der_serializer_setup_defaults(ctx)

    def vscf_alg_info_der_serializer_serialize_inplace(self, ctx, alg_info):
        """Serialize by using internal ASN.1 writer.
        Note, that caller code is responsible to reset ASN.1 writer with
        an output buffer."""
        vscf_alg_info_der_serializer_serialize_inplace = self._lib.vscf_alg_info_der_serializer_serialize_inplace
        vscf_alg_info_der_serializer_serialize_inplace.argtypes = [POINTER(vscf_alg_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_alg_info_der_serializer_serialize_inplace.restype = c_size_t
        return vscf_alg_info_der_serializer_serialize_inplace(ctx, alg_info)

    def vscf_alg_info_der_serializer_shallow_copy(self, ctx):
        vscf_alg_info_der_serializer_shallow_copy = self._lib.vscf_alg_info_der_serializer_shallow_copy
        vscf_alg_info_der_serializer_shallow_copy.argtypes = [POINTER(vscf_alg_info_der_serializer_t)]
        vscf_alg_info_der_serializer_shallow_copy.restype = POINTER(vscf_alg_info_der_serializer_t)
        return vscf_alg_info_der_serializer_shallow_copy(ctx)

    def vscf_alg_info_der_serializer_impl(self, ctx):
        vscf_alg_info_der_serializer_impl = self._lib.vscf_alg_info_der_serializer_impl
        vscf_alg_info_der_serializer_impl.argtypes = [POINTER(vscf_alg_info_der_serializer_t)]
        vscf_alg_info_der_serializer_impl.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_serializer_impl(ctx)
