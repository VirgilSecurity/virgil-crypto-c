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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_impl import vscf_impl_t


class vscf_asn1rd_t(Structure):
    pass


class VscfAsn1rd(object):
    """This is MbedTLS implementation of ASN.1 reader."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_asn1rd_new(self):
        vscf_asn1rd_new = self._lib.vscf_asn1rd_new
        vscf_asn1rd_new.argtypes = []
        vscf_asn1rd_new.restype = POINTER(vscf_asn1rd_t)
        return vscf_asn1rd_new()

    def vscf_asn1rd_delete(self, ctx):
        vscf_asn1rd_delete = self._lib.vscf_asn1rd_delete
        vscf_asn1rd_delete.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_delete.restype = None
        return vscf_asn1rd_delete(ctx)

    def vscf_asn1rd_reset(self, ctx, data):
        """Reset all internal states and prepare to new ASN.1 reading operations."""
        vscf_asn1rd_reset = self._lib.vscf_asn1rd_reset
        vscf_asn1rd_reset.argtypes = [POINTER(vscf_asn1rd_t), vsc_data_t]
        vscf_asn1rd_reset.restype = None
        return vscf_asn1rd_reset(ctx, data)

    def vscf_asn1rd_left_len(self, ctx):
        """Return length in bytes how many bytes are left for reading."""
        vscf_asn1rd_left_len = self._lib.vscf_asn1rd_left_len
        vscf_asn1rd_left_len.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_left_len.restype = c_size_t
        return vscf_asn1rd_left_len(ctx)

    def vscf_asn1rd_has_error(self, ctx):
        """Return true if status is not "success"."""
        vscf_asn1rd_has_error = self._lib.vscf_asn1rd_has_error
        vscf_asn1rd_has_error.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_has_error.restype = c_bool
        return vscf_asn1rd_has_error(ctx)

    def vscf_asn1rd_status(self, ctx):
        """Return error code."""
        vscf_asn1rd_status = self._lib.vscf_asn1rd_status
        vscf_asn1rd_status.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_status.restype = c_int
        return vscf_asn1rd_status(ctx)

    def vscf_asn1rd_get_tag(self, ctx):
        """Get tag of the current ASN.1 element."""
        vscf_asn1rd_get_tag = self._lib.vscf_asn1rd_get_tag
        vscf_asn1rd_get_tag.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_get_tag.restype = c_int
        return vscf_asn1rd_get_tag(ctx)

    def vscf_asn1rd_get_len(self, ctx):
        """Get length of the current ASN.1 element."""
        vscf_asn1rd_get_len = self._lib.vscf_asn1rd_get_len
        vscf_asn1rd_get_len.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_get_len.restype = c_size_t
        return vscf_asn1rd_get_len(ctx)

    def vscf_asn1rd_get_data_len(self, ctx):
        """Get length of the current ASN.1 element with tag and length itself."""
        vscf_asn1rd_get_data_len = self._lib.vscf_asn1rd_get_data_len
        vscf_asn1rd_get_data_len.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_get_data_len.restype = c_size_t
        return vscf_asn1rd_get_data_len(ctx)

    def vscf_asn1rd_read_tag(self, ctx, tag):
        """Read ASN.1 type: TAG.
        Return element length."""
        vscf_asn1rd_read_tag = self._lib.vscf_asn1rd_read_tag
        vscf_asn1rd_read_tag.argtypes = [POINTER(vscf_asn1rd_t), c_int]
        vscf_asn1rd_read_tag.restype = c_size_t
        return vscf_asn1rd_read_tag(ctx, tag)

    def vscf_asn1rd_read_context_tag(self, ctx, tag):
        """Read ASN.1 type: context-specific TAG.
        Return element length.
        Return 0 if current position do not points to the requested tag."""
        vscf_asn1rd_read_context_tag = self._lib.vscf_asn1rd_read_context_tag
        vscf_asn1rd_read_context_tag.argtypes = [POINTER(vscf_asn1rd_t), c_int]
        vscf_asn1rd_read_context_tag.restype = c_size_t
        return vscf_asn1rd_read_context_tag(ctx, tag)

    def vscf_asn1rd_read_int(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_int = self._lib.vscf_asn1rd_read_int
        vscf_asn1rd_read_int.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_int.restype = c_int
        return vscf_asn1rd_read_int(ctx)

    def vscf_asn1rd_read_int8(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_int8 = self._lib.vscf_asn1rd_read_int8
        vscf_asn1rd_read_int8.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_int8.restype = c_int
        return vscf_asn1rd_read_int8(ctx)

    def vscf_asn1rd_read_int16(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_int16 = self._lib.vscf_asn1rd_read_int16
        vscf_asn1rd_read_int16.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_int16.restype = c_int
        return vscf_asn1rd_read_int16(ctx)

    def vscf_asn1rd_read_int32(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_int32 = self._lib.vscf_asn1rd_read_int32
        vscf_asn1rd_read_int32.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_int32.restype = c_int
        return vscf_asn1rd_read_int32(ctx)

    def vscf_asn1rd_read_int64(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_int64 = self._lib.vscf_asn1rd_read_int64
        vscf_asn1rd_read_int64.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_int64.restype = c_int
        return vscf_asn1rd_read_int64(ctx)

    def vscf_asn1rd_read_uint(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_uint = self._lib.vscf_asn1rd_read_uint
        vscf_asn1rd_read_uint.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_uint.restype = c_uint
        return vscf_asn1rd_read_uint(ctx)

    def vscf_asn1rd_read_uint8(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_uint8 = self._lib.vscf_asn1rd_read_uint8
        vscf_asn1rd_read_uint8.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_uint8.restype = c_uint
        return vscf_asn1rd_read_uint8(ctx)

    def vscf_asn1rd_read_uint16(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_uint16 = self._lib.vscf_asn1rd_read_uint16
        vscf_asn1rd_read_uint16.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_uint16.restype = c_uint
        return vscf_asn1rd_read_uint16(ctx)

    def vscf_asn1rd_read_uint32(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_uint32 = self._lib.vscf_asn1rd_read_uint32
        vscf_asn1rd_read_uint32.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_uint32.restype = c_uint
        return vscf_asn1rd_read_uint32(ctx)

    def vscf_asn1rd_read_uint64(self, ctx):
        """Read ASN.1 type: INTEGER."""
        vscf_asn1rd_read_uint64 = self._lib.vscf_asn1rd_read_uint64
        vscf_asn1rd_read_uint64.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_uint64.restype = c_uint
        return vscf_asn1rd_read_uint64(ctx)

    def vscf_asn1rd_read_bool(self, ctx):
        """Read ASN.1 type: BOOLEAN."""
        vscf_asn1rd_read_bool = self._lib.vscf_asn1rd_read_bool
        vscf_asn1rd_read_bool.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_bool.restype = c_bool
        return vscf_asn1rd_read_bool(ctx)

    def vscf_asn1rd_read_null(self, ctx):
        """Read ASN.1 type: NULL."""
        vscf_asn1rd_read_null = self._lib.vscf_asn1rd_read_null
        vscf_asn1rd_read_null.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_null.restype = None
        return vscf_asn1rd_read_null(ctx)

    def vscf_asn1rd_read_null_optional(self, ctx):
        """Read ASN.1 type: NULL, only if it exists.
        Note, this method is safe to call even no more data is left for reading."""
        vscf_asn1rd_read_null_optional = self._lib.vscf_asn1rd_read_null_optional
        vscf_asn1rd_read_null_optional.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_null_optional.restype = None
        return vscf_asn1rd_read_null_optional(ctx)

    def vscf_asn1rd_read_octet_str(self, ctx):
        """Read ASN.1 type: OCTET STRING."""
        vscf_asn1rd_read_octet_str = self._lib.vscf_asn1rd_read_octet_str
        vscf_asn1rd_read_octet_str.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_octet_str.restype = vsc_data_t
        return vscf_asn1rd_read_octet_str(ctx)

    def vscf_asn1rd_read_bitstring_as_octet_str(self, ctx):
        """Read ASN.1 type: BIT STRING."""
        vscf_asn1rd_read_bitstring_as_octet_str = self._lib.vscf_asn1rd_read_bitstring_as_octet_str
        vscf_asn1rd_read_bitstring_as_octet_str.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_bitstring_as_octet_str.restype = vsc_data_t
        return vscf_asn1rd_read_bitstring_as_octet_str(ctx)

    def vscf_asn1rd_read_utf8_str(self, ctx):
        """Read ASN.1 type: UTF8String."""
        vscf_asn1rd_read_utf8_str = self._lib.vscf_asn1rd_read_utf8_str
        vscf_asn1rd_read_utf8_str.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_utf8_str.restype = vsc_data_t
        return vscf_asn1rd_read_utf8_str(ctx)

    def vscf_asn1rd_read_oid(self, ctx):
        """Read ASN.1 type: OID."""
        vscf_asn1rd_read_oid = self._lib.vscf_asn1rd_read_oid
        vscf_asn1rd_read_oid.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_oid.restype = vsc_data_t
        return vscf_asn1rd_read_oid(ctx)

    def vscf_asn1rd_read_data(self, ctx, len):
        """Read raw data of given length."""
        vscf_asn1rd_read_data = self._lib.vscf_asn1rd_read_data
        vscf_asn1rd_read_data.argtypes = [POINTER(vscf_asn1rd_t), c_size_t]
        vscf_asn1rd_read_data.restype = vsc_data_t
        return vscf_asn1rd_read_data(ctx, len)

    def vscf_asn1rd_read_sequence(self, ctx):
        """Read ASN.1 type: CONSTRUCTED | SEQUENCE.
        Return element length."""
        vscf_asn1rd_read_sequence = self._lib.vscf_asn1rd_read_sequence
        vscf_asn1rd_read_sequence.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_sequence.restype = c_size_t
        return vscf_asn1rd_read_sequence(ctx)

    def vscf_asn1rd_read_set(self, ctx):
        """Read ASN.1 type: CONSTRUCTED | SET.
        Return element length."""
        vscf_asn1rd_read_set = self._lib.vscf_asn1rd_read_set
        vscf_asn1rd_read_set.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_read_set.restype = c_size_t
        return vscf_asn1rd_read_set(ctx)

    def vscf_asn1rd_shallow_copy(self, ctx):
        vscf_asn1rd_shallow_copy = self._lib.vscf_asn1rd_shallow_copy
        vscf_asn1rd_shallow_copy.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_shallow_copy.restype = POINTER(vscf_asn1rd_t)
        return vscf_asn1rd_shallow_copy(ctx)

    def vscf_asn1rd_impl(self, ctx):
        vscf_asn1rd_impl = self._lib.vscf_asn1rd_impl
        vscf_asn1rd_impl.argtypes = [POINTER(vscf_asn1rd_t)]
        vscf_asn1rd_impl.restype = POINTER(vscf_impl_t)
        return vscf_asn1rd_impl(ctx)
