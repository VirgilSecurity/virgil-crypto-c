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
from ._c_bridge import VscfPkcs8Serializer
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus
from ._c_bridge._vscf_error import vscf_error_t
from .key_serializer import KeySerializer


class Pkcs8Serializer(KeySerializer):
    """Implements PKCS#8 key serialization to DER format."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_pkcs8_serializer = VscfPkcs8Serializer()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_delete(self.ctx)

    def set_asn1_writer(self, asn1_writer):
        self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_use_asn1_writer(self.ctx, asn1_writer.c_impl)

    def serialized_public_key_len(self, public_key):
        """Calculate buffer size enough to hold serialized public key.

        Precondition: public key must be exportable."""
        result = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_serialized_public_key_len(self.ctx, public_key.ctx)
        return result

    def serialize_public_key(self, public_key):
        """Serialize given public key to an interchangeable format.

        Precondition: public key must be exportable."""
        out = Buffer(self.serialized_public_key_len(public_key=public_key))
        status = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_serialize_public_key(self.ctx, public_key.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def serialized_private_key_len(self, private_key):
        """Calculate buffer size enough to hold serialized private key.

        Precondition: private key must be exportable."""
        result = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_serialized_private_key_len(self.ctx, private_key.ctx)
        return result

    def serialize_private_key(self, private_key):
        """Serialize given private key to an interchangeable format.

        Precondition: private key must be exportable."""
        out = Buffer(self.serialized_private_key_len(private_key=private_key))
        status = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_serialize_private_key(self.ctx, private_key.ctx, out.c_buffer)
        VscfStatus.handle_status(status)
        return out.get_bytes()

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_setup_defaults(self.ctx)

    def serialize_public_key_inplace(self, public_key):
        """Serialize Public Key by using internal ASN.1 writer.
        Note, that caller code is responsible to reset ASN.1 writer with
        an output buffer."""
        error = vscf_error_t()
        result = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_serialize_public_key_inplace(self.ctx, public_key.ctx, error)
        VscfStatus.handle_status(error.status)
        return result

    def serialize_private_key_inplace(self, private_key):
        """Serialize Private Key by using internal ASN.1 writer.
        Note, that caller code is responsible to reset ASN.1 writer with
        an output buffer."""
        error = vscf_error_t()
        result = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_serialize_private_key_inplace(self.ctx, private_key.ctx, error)
        VscfStatus.handle_status(error.status)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_pkcs8_serializer = VscfPkcs8Serializer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_pkcs8_serializer = VscfPkcs8Serializer()
        inst.ctx = inst._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_shallow_copy(value)
        self._c_impl = self._lib_vscf_pkcs8_serializer.vscf_pkcs8_serializer_impl(self.ctx)
