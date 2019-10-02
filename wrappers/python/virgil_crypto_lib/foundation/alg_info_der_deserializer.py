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
from ._c_bridge import VscfAlgInfoDerDeserializer
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus
from .alg_info_deserializer import AlgInfoDeserializer


class AlgInfoDerDeserializer(AlgInfoDeserializer):
    """Provide DER deserializer of algorithm information."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_alg_info_der_deserializer = VscfAlgInfoDerDeserializer()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_delete(self.ctx)

    def set_asn1_reader(self, asn1_reader):
        self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_use_asn1_reader(self.ctx, asn1_reader.c_impl)

    def deserialize(self, data):
        """Deserialize algorithm from the data."""
        d_data = Data(data)
        error = vscf_error_t()
        result = self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_deserialize(self.ctx, d_data.data, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_setup_defaults(self.ctx)

    def deserialize_inplace(self):
        """Deserialize by using internal ASN.1 reader.
        Note, that caller code is responsible to reset ASN.1 reader with
        an input buffer."""
        error = vscf_error_t()
        result = self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_deserialize_inplace(self.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_alg_info_der_deserializer = VscfAlgInfoDerDeserializer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_alg_info_der_deserializer = VscfAlgInfoDerDeserializer()
        inst.ctx = inst._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_shallow_copy(value)
        self._c_impl = self._lib_vscf_alg_info_der_deserializer.vscf_alg_info_der_deserializer_impl(self.ctx)
