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
from ._vscf_raw_public_key import vscf_raw_public_key_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscf_raw_private_key import vscf_raw_private_key_t
from ._vscf_error import vscf_error_t


class vscf_sec1_serializer_t(Structure):
    pass


class VscfSec1Serializer(object):
    """Implements SEC 1 key serialization to DER format.
    See also RFC 5480 and RFC 5915."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_sec1_serializer_new(self):
        vscf_sec1_serializer_new = self._lib.vscf_sec1_serializer_new
        vscf_sec1_serializer_new.argtypes = []
        vscf_sec1_serializer_new.restype = POINTER(vscf_sec1_serializer_t)
        return vscf_sec1_serializer_new()

    def vscf_sec1_serializer_delete(self, ctx):
        vscf_sec1_serializer_delete = self._lib.vscf_sec1_serializer_delete
        vscf_sec1_serializer_delete.argtypes = [POINTER(vscf_sec1_serializer_t)]
        vscf_sec1_serializer_delete.restype = None
        return vscf_sec1_serializer_delete(ctx)

    def vscf_sec1_serializer_use_asn1_writer(self, ctx, asn1_writer):
        vscf_sec1_serializer_use_asn1_writer = self._lib.vscf_sec1_serializer_use_asn1_writer
        vscf_sec1_serializer_use_asn1_writer.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_impl_t)]
        vscf_sec1_serializer_use_asn1_writer.restype = None
        return vscf_sec1_serializer_use_asn1_writer(ctx, asn1_writer)

    def vscf_sec1_serializer_serialized_public_key_len(self, ctx, public_key):
        """Calculate buffer size enough to hold serialized public key.

        Precondition: public key must be exportable."""
        vscf_sec1_serializer_serialized_public_key_len = self._lib.vscf_sec1_serializer_serialized_public_key_len
        vscf_sec1_serializer_serialized_public_key_len.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_raw_public_key_t)]
        vscf_sec1_serializer_serialized_public_key_len.restype = c_size_t
        return vscf_sec1_serializer_serialized_public_key_len(ctx, public_key)

    def vscf_sec1_serializer_serialize_public_key(self, ctx, public_key, out):
        """Serialize given public key to an interchangeable format.

        Precondition: public key must be exportable."""
        vscf_sec1_serializer_serialize_public_key = self._lib.vscf_sec1_serializer_serialize_public_key
        vscf_sec1_serializer_serialize_public_key.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_raw_public_key_t), POINTER(vsc_buffer_t)]
        vscf_sec1_serializer_serialize_public_key.restype = c_int
        return vscf_sec1_serializer_serialize_public_key(ctx, public_key, out)

    def vscf_sec1_serializer_serialized_private_key_len(self, ctx, private_key):
        """Calculate buffer size enough to hold serialized private key.

        Precondition: private key must be exportable."""
        vscf_sec1_serializer_serialized_private_key_len = self._lib.vscf_sec1_serializer_serialized_private_key_len
        vscf_sec1_serializer_serialized_private_key_len.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_raw_private_key_t)]
        vscf_sec1_serializer_serialized_private_key_len.restype = c_size_t
        return vscf_sec1_serializer_serialized_private_key_len(ctx, private_key)

    def vscf_sec1_serializer_serialize_private_key(self, ctx, private_key, out):
        """Serialize given private key to an interchangeable format.

        Precondition: private key must be exportable."""
        vscf_sec1_serializer_serialize_private_key = self._lib.vscf_sec1_serializer_serialize_private_key
        vscf_sec1_serializer_serialize_private_key.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_raw_private_key_t), POINTER(vsc_buffer_t)]
        vscf_sec1_serializer_serialize_private_key.restype = c_int
        return vscf_sec1_serializer_serialize_private_key(ctx, private_key, out)

    def vscf_sec1_serializer_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_sec1_serializer_setup_defaults = self._lib.vscf_sec1_serializer_setup_defaults
        vscf_sec1_serializer_setup_defaults.argtypes = [POINTER(vscf_sec1_serializer_t)]
        vscf_sec1_serializer_setup_defaults.restype = None
        return vscf_sec1_serializer_setup_defaults(ctx)

    def vscf_sec1_serializer_serialize_public_key_inplace(self, ctx, public_key, error):
        """Serialize Public Key by using internal ASN.1 writer.
        Note, that caller code is responsible to reset ASN.1 writer with
        an output buffer."""
        vscf_sec1_serializer_serialize_public_key_inplace = self._lib.vscf_sec1_serializer_serialize_public_key_inplace
        vscf_sec1_serializer_serialize_public_key_inplace.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_raw_public_key_t), POINTER(vscf_error_t)]
        vscf_sec1_serializer_serialize_public_key_inplace.restype = c_size_t
        return vscf_sec1_serializer_serialize_public_key_inplace(ctx, public_key, error)

    def vscf_sec1_serializer_serialize_private_key_inplace(self, ctx, private_key, error):
        """Serialize Private Key by using internal ASN.1 writer.
        Note, that caller code is responsible to reset ASN.1 writer with
        an output buffer."""
        vscf_sec1_serializer_serialize_private_key_inplace = self._lib.vscf_sec1_serializer_serialize_private_key_inplace
        vscf_sec1_serializer_serialize_private_key_inplace.argtypes = [POINTER(vscf_sec1_serializer_t), POINTER(vscf_raw_private_key_t), POINTER(vscf_error_t)]
        vscf_sec1_serializer_serialize_private_key_inplace.restype = c_size_t
        return vscf_sec1_serializer_serialize_private_key_inplace(ctx, private_key, error)

    def vscf_sec1_serializer_shallow_copy(self, ctx):
        vscf_sec1_serializer_shallow_copy = self._lib.vscf_sec1_serializer_shallow_copy
        vscf_sec1_serializer_shallow_copy.argtypes = [POINTER(vscf_sec1_serializer_t)]
        vscf_sec1_serializer_shallow_copy.restype = POINTER(vscf_sec1_serializer_t)
        return vscf_sec1_serializer_shallow_copy(ctx)

    def vscf_sec1_serializer_impl(self, ctx):
        vscf_sec1_serializer_impl = self._lib.vscf_sec1_serializer_impl
        vscf_sec1_serializer_impl.argtypes = [POINTER(vscf_sec1_serializer_t)]
        vscf_sec1_serializer_impl.restype = POINTER(vscf_impl_t)
        return vscf_sec1_serializer_impl(ctx)
