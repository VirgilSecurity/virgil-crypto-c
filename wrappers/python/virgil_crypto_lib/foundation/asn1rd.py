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
from ._c_bridge import VscfAsn1rd
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge import VscfStatus
from .asn1_reader import Asn1Reader


class Asn1rd(Asn1Reader):
    """This is MbedTLS implementation of ASN.1 reader."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_asn1rd = VscfAsn1rd()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_asn1rd.vscf_asn1rd_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_asn1rd.vscf_asn1rd_delete(self.ctx)

    def reset(self, data):
        """Reset all internal states and prepare to new ASN.1 reading operations."""
        d_data = Data(data)
        self._lib_vscf_asn1rd.vscf_asn1rd_reset(self.ctx, d_data.data)

    def left_len(self):
        """Return length in bytes how many bytes are left for reading."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_left_len(self.ctx)
        return result

    def has_error(self):
        """Return true if status is not "success"."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_has_error(self.ctx)
        return result

    def status(self):
        """Return error code."""
        status = self._lib_vscf_asn1rd.vscf_asn1rd_status(self.ctx)
        VscfStatus.handle_status(status)

    def get_tag(self):
        """Get tag of the current ASN.1 element."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_get_tag(self.ctx)
        return result

    def get_len(self):
        """Get length of the current ASN.1 element."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_get_len(self.ctx)
        return result

    def get_data_len(self):
        """Get length of the current ASN.1 element with tag and length itself."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_get_data_len(self.ctx)
        return result

    def read_tag(self, tag):
        """Read ASN.1 type: TAG.
        Return element length."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_tag(self.ctx, tag)
        return result

    def read_context_tag(self, tag):
        """Read ASN.1 type: context-specific TAG.
        Return element length.
        Return 0 if current position do not points to the requested tag."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_context_tag(self.ctx, tag)
        return result

    def read_int(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_int(self.ctx)
        return result

    def read_int8(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_int8(self.ctx)
        return result

    def read_int16(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_int16(self.ctx)
        return result

    def read_int32(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_int32(self.ctx)
        return result

    def read_int64(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_int64(self.ctx)
        return result

    def read_uint(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_uint(self.ctx)
        return result

    def read_uint8(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_uint8(self.ctx)
        return result

    def read_uint16(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_uint16(self.ctx)
        return result

    def read_uint32(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_uint32(self.ctx)
        return result

    def read_uint64(self):
        """Read ASN.1 type: INTEGER."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_uint64(self.ctx)
        return result

    def read_bool(self):
        """Read ASN.1 type: BOOLEAN."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_bool(self.ctx)
        return result

    def read_null(self):
        """Read ASN.1 type: NULL."""
        self._lib_vscf_asn1rd.vscf_asn1rd_read_null(self.ctx)

    def read_null_optional(self):
        """Read ASN.1 type: NULL, only if it exists.
        Note, this method is safe to call even no more data is left for reading."""
        self._lib_vscf_asn1rd.vscf_asn1rd_read_null_optional(self.ctx)

    def read_octet_str(self):
        """Read ASN.1 type: OCTET STRING."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_octet_str(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def read_bitstring_as_octet_str(self):
        """Read ASN.1 type: BIT STRING."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_bitstring_as_octet_str(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def read_utf8_str(self):
        """Read ASN.1 type: UTF8String."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_utf8_str(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def read_oid(self):
        """Read ASN.1 type: OID."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_oid(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def read_data(self, len):
        """Read raw data of given length."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_data(self.ctx, len)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def read_sequence(self):
        """Read ASN.1 type: SEQUENCE.
        Return element length."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_sequence(self.ctx)
        return result

    def read_set(self):
        """Read ASN.1 type: SET.
        Return element length."""
        result = self._lib_vscf_asn1rd.vscf_asn1rd_read_set(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_asn1rd = VscfAsn1rd()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_asn1rd = VscfAsn1rd()
        inst.ctx = inst._lib_vscf_asn1rd.vscf_asn1rd_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_asn1rd.vscf_asn1rd_shallow_copy(value)
        self._c_impl = self._lib_vscf_asn1rd.vscf_asn1rd_impl(self.ctx)
