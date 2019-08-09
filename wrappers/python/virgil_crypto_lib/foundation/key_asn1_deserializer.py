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
from ._c_bridge import VscfKeyAsn1Deserializer
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfStatus
from .key_deserializer import KeyDeserializer


class KeyAsn1Deserializer(KeyDeserializer):
    """Implements PKCS#8 and SEC1 key deserialization from DER / PEM format."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_key_asn1_deserializer = VscfKeyAsn1Deserializer()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_delete(self.ctx)

    def set_asn1_reader(self, asn1_reader):
        self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_use_asn1_reader(self.ctx, asn1_reader.c_impl)

    def deserialize_public_key(self, public_key_data):
        """Deserialize given public key as an interchangeable format to the object."""
        d_public_key_data = Data(public_key_data)
        error = vscf_error_t()
        result = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_deserialize_public_key(self.ctx, d_public_key_data.data, error)
        VscfStatus.handle_status(error.status)
        return result

    def deserialize_private_key(self, private_key_data):
        """Deserialize given private key as an interchangeable format to the object."""
        d_private_key_data = Data(private_key_data)
        error = vscf_error_t()
        result = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_deserialize_private_key(self.ctx, d_private_key_data.data, error)
        VscfStatus.handle_status(error.status)
        return result

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_setup_defaults(self.ctx)

    def deserialize_public_key_inplace(self):
        """Deserialize Public Key by using internal ASN.1 reader.
        Note, that caller code is responsible to reset ASN.1 reader with
        an input buffer."""
        error = vscf_error_t()
        result = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_deserialize_public_key_inplace(self.ctx, error)
        VscfStatus.handle_status(error.status)
        return result

    def deserialize_private_key_inplace(self):
        """Deserialize Private Key by using internal ASN.1 reader.
        Note, that caller code is responsible to reset ASN.1 reader with
        an input buffer."""
        error = vscf_error_t()
        result = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_deserialize_private_key_inplace(self.ctx, error)
        VscfStatus.handle_status(error.status)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_asn1_deserializer = VscfKeyAsn1Deserializer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_asn1_deserializer = VscfKeyAsn1Deserializer()
        inst.ctx = inst._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_shallow_copy(value)
        self._c_impl = self._lib_vscf_key_asn1_deserializer.vscf_key_asn1_deserializer_impl(self.ctx)
