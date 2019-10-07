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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_error import vscf_error_t
from ._vscf_raw_public_key import vscf_raw_public_key_t
from ._vscf_raw_private_key import vscf_raw_private_key_t


class vscf_key_asn1_deserializer_t(Structure):
    pass


class VscfKeyAsn1Deserializer(object):
    """Implements PKCS#8 and SEC1 key deserialization from DER / PEM format."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_key_asn1_deserializer_new(self):
        vscf_key_asn1_deserializer_new = self._lib.vscf_key_asn1_deserializer_new
        vscf_key_asn1_deserializer_new.argtypes = []
        vscf_key_asn1_deserializer_new.restype = POINTER(vscf_key_asn1_deserializer_t)
        return vscf_key_asn1_deserializer_new()

    def vscf_key_asn1_deserializer_delete(self, ctx):
        vscf_key_asn1_deserializer_delete = self._lib.vscf_key_asn1_deserializer_delete
        vscf_key_asn1_deserializer_delete.argtypes = [POINTER(vscf_key_asn1_deserializer_t)]
        vscf_key_asn1_deserializer_delete.restype = None
        return vscf_key_asn1_deserializer_delete(ctx)

    def vscf_key_asn1_deserializer_use_asn1_reader(self, ctx, asn1_reader):
        vscf_key_asn1_deserializer_use_asn1_reader = self._lib.vscf_key_asn1_deserializer_use_asn1_reader
        vscf_key_asn1_deserializer_use_asn1_reader.argtypes = [POINTER(vscf_key_asn1_deserializer_t), POINTER(vscf_impl_t)]
        vscf_key_asn1_deserializer_use_asn1_reader.restype = None
        return vscf_key_asn1_deserializer_use_asn1_reader(ctx, asn1_reader)

    def vscf_key_asn1_deserializer_deserialize_public_key(self, ctx, public_key_data, error):
        """Deserialize given public key as an interchangeable format to the object."""
        vscf_key_asn1_deserializer_deserialize_public_key = self._lib.vscf_key_asn1_deserializer_deserialize_public_key
        vscf_key_asn1_deserializer_deserialize_public_key.argtypes = [POINTER(vscf_key_asn1_deserializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_key_asn1_deserializer_deserialize_public_key.restype = POINTER(vscf_raw_public_key_t)
        return vscf_key_asn1_deserializer_deserialize_public_key(ctx, public_key_data, error)

    def vscf_key_asn1_deserializer_deserialize_private_key(self, ctx, private_key_data, error):
        """Deserialize given private key as an interchangeable format to the object."""
        vscf_key_asn1_deserializer_deserialize_private_key = self._lib.vscf_key_asn1_deserializer_deserialize_private_key
        vscf_key_asn1_deserializer_deserialize_private_key.argtypes = [POINTER(vscf_key_asn1_deserializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_key_asn1_deserializer_deserialize_private_key.restype = POINTER(vscf_raw_private_key_t)
        return vscf_key_asn1_deserializer_deserialize_private_key(ctx, private_key_data, error)

    def vscf_key_asn1_deserializer_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_key_asn1_deserializer_setup_defaults = self._lib.vscf_key_asn1_deserializer_setup_defaults
        vscf_key_asn1_deserializer_setup_defaults.argtypes = [POINTER(vscf_key_asn1_deserializer_t)]
        vscf_key_asn1_deserializer_setup_defaults.restype = None
        return vscf_key_asn1_deserializer_setup_defaults(ctx)

    def vscf_key_asn1_deserializer_deserialize_public_key_inplace(self, ctx, error):
        """Deserialize Public Key by using internal ASN.1 reader.
        Note, that caller code is responsible to reset ASN.1 reader with
        an input buffer."""
        vscf_key_asn1_deserializer_deserialize_public_key_inplace = self._lib.vscf_key_asn1_deserializer_deserialize_public_key_inplace
        vscf_key_asn1_deserializer_deserialize_public_key_inplace.argtypes = [POINTER(vscf_key_asn1_deserializer_t), POINTER(vscf_error_t)]
        vscf_key_asn1_deserializer_deserialize_public_key_inplace.restype = POINTER(vscf_raw_public_key_t)
        return vscf_key_asn1_deserializer_deserialize_public_key_inplace(ctx, error)

    def vscf_key_asn1_deserializer_deserialize_private_key_inplace(self, ctx, error):
        """Deserialize Private Key by using internal ASN.1 reader.
        Note, that caller code is responsible to reset ASN.1 reader with
        an input buffer."""
        vscf_key_asn1_deserializer_deserialize_private_key_inplace = self._lib.vscf_key_asn1_deserializer_deserialize_private_key_inplace
        vscf_key_asn1_deserializer_deserialize_private_key_inplace.argtypes = [POINTER(vscf_key_asn1_deserializer_t), POINTER(vscf_error_t)]
        vscf_key_asn1_deserializer_deserialize_private_key_inplace.restype = POINTER(vscf_raw_private_key_t)
        return vscf_key_asn1_deserializer_deserialize_private_key_inplace(ctx, error)

    def vscf_key_asn1_deserializer_shallow_copy(self, ctx):
        vscf_key_asn1_deserializer_shallow_copy = self._lib.vscf_key_asn1_deserializer_shallow_copy
        vscf_key_asn1_deserializer_shallow_copy.argtypes = [POINTER(vscf_key_asn1_deserializer_t)]
        vscf_key_asn1_deserializer_shallow_copy.restype = POINTER(vscf_key_asn1_deserializer_t)
        return vscf_key_asn1_deserializer_shallow_copy(ctx)

    def vscf_key_asn1_deserializer_impl(self, ctx):
        vscf_key_asn1_deserializer_impl = self._lib.vscf_key_asn1_deserializer_impl
        vscf_key_asn1_deserializer_impl.argtypes = [POINTER(vscf_key_asn1_deserializer_t)]
        vscf_key_asn1_deserializer_impl.restype = POINTER(vscf_impl_t)
        return vscf_key_asn1_deserializer_impl(ctx)
