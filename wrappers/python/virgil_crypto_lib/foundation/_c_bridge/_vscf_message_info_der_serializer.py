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
from ._vscf_message_info import vscf_message_info_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_error import vscf_error_t
from ._vscf_message_info_footer import vscf_message_info_footer_t


class vscf_message_info_der_serializer_t(Structure):
    pass


class VscfMessageInfoDerSerializer(object):
    """CMS based serialization of the class "message info"."""

    PREFIX_LEN = 32

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_der_serializer_new(self):
        vscf_message_info_der_serializer_new = self._lib.vscf_message_info_der_serializer_new
        vscf_message_info_der_serializer_new.argtypes = []
        vscf_message_info_der_serializer_new.restype = POINTER(vscf_message_info_der_serializer_t)
        return vscf_message_info_der_serializer_new()

    def vscf_message_info_der_serializer_delete(self, ctx):
        vscf_message_info_der_serializer_delete = self._lib.vscf_message_info_der_serializer_delete
        vscf_message_info_der_serializer_delete.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_delete.restype = None
        return vscf_message_info_der_serializer_delete(ctx)

    def vscf_message_info_der_serializer_use_asn1_reader(self, ctx, asn1_reader):
        vscf_message_info_der_serializer_use_asn1_reader = self._lib.vscf_message_info_der_serializer_use_asn1_reader
        vscf_message_info_der_serializer_use_asn1_reader.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_message_info_der_serializer_use_asn1_reader.restype = None
        return vscf_message_info_der_serializer_use_asn1_reader(ctx, asn1_reader)

    def vscf_message_info_der_serializer_use_asn1_writer(self, ctx, asn1_writer):
        vscf_message_info_der_serializer_use_asn1_writer = self._lib.vscf_message_info_der_serializer_use_asn1_writer
        vscf_message_info_der_serializer_use_asn1_writer.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_message_info_der_serializer_use_asn1_writer.restype = None
        return vscf_message_info_der_serializer_use_asn1_writer(ctx, asn1_writer)

    def vscf_message_info_der_serializer_serialized_len(self, ctx, message_info):
        """Return buffer size enough to hold serialized message info."""
        vscf_message_info_der_serializer_serialized_len = self._lib.vscf_message_info_der_serializer_serialized_len
        vscf_message_info_der_serializer_serialized_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialized_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_len(ctx, message_info)

    def vscf_message_info_der_serializer_serialize(self, ctx, message_info, out):
        """Serialize class "message info"."""
        vscf_message_info_der_serializer_serialize = self._lib.vscf_message_info_der_serializer_serialize
        vscf_message_info_der_serializer_serialize.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vsc_buffer_t)]
        vscf_message_info_der_serializer_serialize.restype = None
        return vscf_message_info_der_serializer_serialize(ctx, message_info, out)

    def vscf_message_info_der_serializer_read_prefix(self, ctx, data):
        """Read message info prefix from the given data, and if it is valid,
        return a length of bytes of the whole message info.

        Zero returned if length can not be determined from the given data,
        and this means that there is no message info at the data beginning."""
        vscf_message_info_der_serializer_read_prefix = self._lib.vscf_message_info_der_serializer_read_prefix
        vscf_message_info_der_serializer_read_prefix.argtypes = [POINTER(vscf_message_info_der_serializer_t), vsc_data_t]
        vscf_message_info_der_serializer_read_prefix.restype = c_size_t
        return vscf_message_info_der_serializer_read_prefix(ctx, data)

    def vscf_message_info_der_serializer_deserialize(self, ctx, data, error):
        """Deserialize class "message info"."""
        vscf_message_info_der_serializer_deserialize = self._lib.vscf_message_info_der_serializer_deserialize
        vscf_message_info_der_serializer_deserialize.argtypes = [POINTER(vscf_message_info_der_serializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize.restype = POINTER(vscf_message_info_t)
        return vscf_message_info_der_serializer_deserialize(ctx, data, error)

    def vscf_message_info_der_serializer_serialized_footer_len(self, ctx, message_info_footer):
        """Return buffer size enough to hold serialized message info footer."""
        vscf_message_info_der_serializer_serialized_footer_len = self._lib.vscf_message_info_der_serializer_serialized_footer_len
        vscf_message_info_der_serializer_serialized_footer_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t)]
        vscf_message_info_der_serializer_serialized_footer_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_footer_len(ctx, message_info_footer)

    def vscf_message_info_der_serializer_serialize_footer(self, ctx, message_info_footer, out):
        """Serialize class "message info footer"."""
        vscf_message_info_der_serializer_serialize_footer = self._lib.vscf_message_info_der_serializer_serialize_footer
        vscf_message_info_der_serializer_serialize_footer.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t), POINTER(vsc_buffer_t)]
        vscf_message_info_der_serializer_serialize_footer.restype = None
        return vscf_message_info_der_serializer_serialize_footer(ctx, message_info_footer, out)

    def vscf_message_info_der_serializer_deserialize_footer(self, ctx, data, error):
        """Deserialize class "message info footer"."""
        vscf_message_info_der_serializer_deserialize_footer = self._lib.vscf_message_info_der_serializer_deserialize_footer
        vscf_message_info_der_serializer_deserialize_footer.argtypes = [POINTER(vscf_message_info_der_serializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_footer.restype = POINTER(vscf_message_info_footer_t)
        return vscf_message_info_der_serializer_deserialize_footer(ctx, data, error)

    def vscf_message_info_der_serializer_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_message_info_der_serializer_setup_defaults = self._lib.vscf_message_info_der_serializer_setup_defaults
        vscf_message_info_der_serializer_setup_defaults.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_setup_defaults.restype = None
        return vscf_message_info_der_serializer_setup_defaults(ctx)

    def vscf_message_info_der_serializer_shallow_copy(self, ctx):
        vscf_message_info_der_serializer_shallow_copy = self._lib.vscf_message_info_der_serializer_shallow_copy
        vscf_message_info_der_serializer_shallow_copy.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_shallow_copy.restype = POINTER(vscf_message_info_der_serializer_t)
        return vscf_message_info_der_serializer_shallow_copy(ctx)

    def vscf_message_info_der_serializer_impl(self, ctx):
        vscf_message_info_der_serializer_impl = self._lib.vscf_message_info_der_serializer_impl
        vscf_message_info_der_serializer_impl.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_impl.restype = POINTER(vscf_impl_t)
        return vscf_message_info_der_serializer_impl(ctx)
