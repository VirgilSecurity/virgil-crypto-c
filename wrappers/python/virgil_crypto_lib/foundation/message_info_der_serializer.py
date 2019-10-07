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
from ._c_bridge import VscfMessageInfoDerSerializer
from virgil_crypto_lib.common._c_bridge import Buffer
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscf_error import vscf_error_t
from .message_info import MessageInfo
from ._c_bridge import VscfStatus
from .message_info_footer import MessageInfoFooter
from .message_info_serializer import MessageInfoSerializer
from .message_info_footer_serializer import MessageInfoFooterSerializer


class MessageInfoDerSerializer(MessageInfoSerializer, MessageInfoFooterSerializer):
    """CMS based serialization of the class "message info"."""

    PREFIX_LEN = 32

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_message_info_der_serializer = VscfMessageInfoDerSerializer()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_delete(self.ctx)

    def set_asn1_reader(self, asn1_reader):
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_use_asn1_reader(self.ctx, asn1_reader.c_impl)

    def set_asn1_writer(self, asn1_writer):
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_use_asn1_writer(self.ctx, asn1_writer.c_impl)

    def serialized_len(self, message_info):
        """Return buffer size enough to hold serialized message info."""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_len(self.ctx, message_info.ctx)
        return result

    def serialize(self, message_info):
        """Serialize class "message info"."""
        out = Buffer(self.serialized_len(message_info=message_info))
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize(self.ctx, message_info.ctx, out.c_buffer)
        return out.get_bytes()

    def read_prefix(self, data):
        """Read message info prefix from the given data, and if it is valid,
        return a length of bytes of the whole message info.

        Zero returned if length can not be determined from the given data,
        and this means that there is no message info at the data beginning."""
        d_data = Data(data)
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_read_prefix(self.ctx, d_data.data)
        return result

    def deserialize(self, data):
        """Deserialize class "message info"."""
        d_data = Data(data)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize(self.ctx, d_data.data, error)
        VscfStatus.handle_status(error.status)
        instance = MessageInfo.take_c_ctx(result)
        return instance

    def serialized_footer_len(self, message_info_footer):
        """Return buffer size enough to hold serialized message info footer."""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_footer_len(self.ctx, message_info_footer.ctx)
        return result

    def serialize_footer(self, message_info_footer):
        """Serialize class "message info footer"."""
        out = Buffer(self.serialized_footer_len(message_info_footer=message_info_footer))
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_footer(self.ctx, message_info_footer.ctx, out.c_buffer)
        return out.get_bytes()

    def deserialize_footer(self, data):
        """Deserialize class "message info footer"."""
        d_data = Data(data)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_footer(self.ctx, d_data.data, error)
        VscfStatus.handle_status(error.status)
        instance = MessageInfoFooter.take_c_ctx(result)
        return instance

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_setup_defaults(self.ctx)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_der_serializer = VscfMessageInfoDerSerializer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_der_serializer = VscfMessageInfoDerSerializer()
        inst.ctx = inst._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_shallow_copy(value)
        self._c_impl = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_impl(self.ctx)
