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


class vscf_asn1wr_t(Structure):
    pass


class VscfAsn1wr(object):
    """This is MbedTLS implementation of ASN.1 writer."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_asn1wr_new(self):
        vscf_asn1wr_new = self._lib.vscf_asn1wr_new
        vscf_asn1wr_new.argtypes = []
        vscf_asn1wr_new.restype = POINTER(vscf_asn1wr_t)
        return vscf_asn1wr_new()

    def vscf_asn1wr_delete(self, ctx):
        vscf_asn1wr_delete = self._lib.vscf_asn1wr_delete
        vscf_asn1wr_delete.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_delete.restype = None
        return vscf_asn1wr_delete(ctx)

    def vscf_asn1wr_reset(self, ctx, out, out_len):
        """Reset all internal states and prepare to new ASN.1 writing operations."""
        vscf_asn1wr_reset = self._lib.vscf_asn1wr_reset
        vscf_asn1wr_reset.argtypes = [POINTER(vscf_asn1wr_t), POINTER(c_byte), c_size_t]
        vscf_asn1wr_reset.restype = None
        return vscf_asn1wr_reset(ctx, out, out_len)

    def vscf_asn1wr_finish(self, ctx, do_not_adjust):
        """Finalize writing and forbid further operations.

        Note, that ASN.1 structure is always written to the buffer end, and
        if argument "do not adjust" is false, then data is moved to the
        beginning, otherwise - data is left at the buffer end.

        Returns length of the written bytes."""
        vscf_asn1wr_finish = self._lib.vscf_asn1wr_finish
        vscf_asn1wr_finish.argtypes = [POINTER(vscf_asn1wr_t), c_bool]
        vscf_asn1wr_finish.restype = c_size_t
        return vscf_asn1wr_finish(ctx, do_not_adjust)

    def vscf_asn1wr_bytes(self, ctx):
        """Returns pointer to the inner buffer."""
        vscf_asn1wr_bytes = self._lib.vscf_asn1wr_bytes
        vscf_asn1wr_bytes.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_bytes.restype = POINTER(POINTER(c_byte))
        return vscf_asn1wr_bytes(ctx)

    def vscf_asn1wr_len(self, ctx):
        """Returns total inner buffer length."""
        vscf_asn1wr_len = self._lib.vscf_asn1wr_len
        vscf_asn1wr_len.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_len.restype = c_size_t
        return vscf_asn1wr_len(ctx)

    def vscf_asn1wr_written_len(self, ctx):
        """Returns how many bytes were already written to the ASN.1 structure."""
        vscf_asn1wr_written_len = self._lib.vscf_asn1wr_written_len
        vscf_asn1wr_written_len.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_written_len.restype = c_size_t
        return vscf_asn1wr_written_len(ctx)

    def vscf_asn1wr_unwritten_len(self, ctx):
        """Returns how many bytes are available for writing."""
        vscf_asn1wr_unwritten_len = self._lib.vscf_asn1wr_unwritten_len
        vscf_asn1wr_unwritten_len.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_unwritten_len.restype = c_size_t
        return vscf_asn1wr_unwritten_len(ctx)

    def vscf_asn1wr_has_error(self, ctx):
        """Return true if status is not "success"."""
        vscf_asn1wr_has_error = self._lib.vscf_asn1wr_has_error
        vscf_asn1wr_has_error.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_has_error.restype = c_bool
        return vscf_asn1wr_has_error(ctx)

    def vscf_asn1wr_status(self, ctx):
        """Return error code."""
        vscf_asn1wr_status = self._lib.vscf_asn1wr_status
        vscf_asn1wr_status.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_status.restype = c_int
        return vscf_asn1wr_status(ctx)

    def vscf_asn1wr_reserve(self, ctx, len):
        """Move writing position backward for the given length.
        Return current writing position."""
        vscf_asn1wr_reserve = self._lib.vscf_asn1wr_reserve
        vscf_asn1wr_reserve.argtypes = [POINTER(vscf_asn1wr_t), c_size_t]
        vscf_asn1wr_reserve.restype = POINTER(POINTER(c_byte))
        return vscf_asn1wr_reserve(ctx, len)

    def vscf_asn1wr_write_tag(self, ctx, tag):
        """Write ASN.1 tag.
        Return count of written bytes."""
        vscf_asn1wr_write_tag = self._lib.vscf_asn1wr_write_tag
        vscf_asn1wr_write_tag.argtypes = [POINTER(vscf_asn1wr_t), c_int]
        vscf_asn1wr_write_tag.restype = c_size_t
        return vscf_asn1wr_write_tag(ctx, tag)

    def vscf_asn1wr_write_context_tag(self, ctx, tag, len):
        """Write context-specific ASN.1 tag.
        Return count of written bytes."""
        vscf_asn1wr_write_context_tag = self._lib.vscf_asn1wr_write_context_tag
        vscf_asn1wr_write_context_tag.argtypes = [POINTER(vscf_asn1wr_t), c_int, c_size_t]
        vscf_asn1wr_write_context_tag.restype = c_size_t
        return vscf_asn1wr_write_context_tag(ctx, tag, len)

    def vscf_asn1wr_write_len(self, ctx, len):
        """Write length of the following data.
        Return count of written bytes."""
        vscf_asn1wr_write_len = self._lib.vscf_asn1wr_write_len
        vscf_asn1wr_write_len.argtypes = [POINTER(vscf_asn1wr_t), c_size_t]
        vscf_asn1wr_write_len.restype = c_size_t
        return vscf_asn1wr_write_len(ctx, len)

    def vscf_asn1wr_write_int(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_int = self._lib.vscf_asn1wr_write_int
        vscf_asn1wr_write_int.argtypes = [POINTER(vscf_asn1wr_t), c_int]
        vscf_asn1wr_write_int.restype = c_size_t
        return vscf_asn1wr_write_int(ctx, value)

    def vscf_asn1wr_write_int8(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_int8 = self._lib.vscf_asn1wr_write_int8
        vscf_asn1wr_write_int8.argtypes = [POINTER(vscf_asn1wr_t), c_int]
        vscf_asn1wr_write_int8.restype = c_size_t
        return vscf_asn1wr_write_int8(ctx, value)

    def vscf_asn1wr_write_int16(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_int16 = self._lib.vscf_asn1wr_write_int16
        vscf_asn1wr_write_int16.argtypes = [POINTER(vscf_asn1wr_t), c_int]
        vscf_asn1wr_write_int16.restype = c_size_t
        return vscf_asn1wr_write_int16(ctx, value)

    def vscf_asn1wr_write_int32(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_int32 = self._lib.vscf_asn1wr_write_int32
        vscf_asn1wr_write_int32.argtypes = [POINTER(vscf_asn1wr_t), c_int]
        vscf_asn1wr_write_int32.restype = c_size_t
        return vscf_asn1wr_write_int32(ctx, value)

    def vscf_asn1wr_write_int64(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_int64 = self._lib.vscf_asn1wr_write_int64
        vscf_asn1wr_write_int64.argtypes = [POINTER(vscf_asn1wr_t), c_int]
        vscf_asn1wr_write_int64.restype = c_size_t
        return vscf_asn1wr_write_int64(ctx, value)

    def vscf_asn1wr_write_uint(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_uint = self._lib.vscf_asn1wr_write_uint
        vscf_asn1wr_write_uint.argtypes = [POINTER(vscf_asn1wr_t), c_uint]
        vscf_asn1wr_write_uint.restype = c_size_t
        return vscf_asn1wr_write_uint(ctx, value)

    def vscf_asn1wr_write_uint8(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_uint8 = self._lib.vscf_asn1wr_write_uint8
        vscf_asn1wr_write_uint8.argtypes = [POINTER(vscf_asn1wr_t), c_uint]
        vscf_asn1wr_write_uint8.restype = c_size_t
        return vscf_asn1wr_write_uint8(ctx, value)

    def vscf_asn1wr_write_uint16(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_uint16 = self._lib.vscf_asn1wr_write_uint16
        vscf_asn1wr_write_uint16.argtypes = [POINTER(vscf_asn1wr_t), c_uint]
        vscf_asn1wr_write_uint16.restype = c_size_t
        return vscf_asn1wr_write_uint16(ctx, value)

    def vscf_asn1wr_write_uint32(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_uint32 = self._lib.vscf_asn1wr_write_uint32
        vscf_asn1wr_write_uint32.argtypes = [POINTER(vscf_asn1wr_t), c_uint]
        vscf_asn1wr_write_uint32.restype = c_size_t
        return vscf_asn1wr_write_uint32(ctx, value)

    def vscf_asn1wr_write_uint64(self, ctx, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        vscf_asn1wr_write_uint64 = self._lib.vscf_asn1wr_write_uint64
        vscf_asn1wr_write_uint64.argtypes = [POINTER(vscf_asn1wr_t), c_uint]
        vscf_asn1wr_write_uint64.restype = c_size_t
        return vscf_asn1wr_write_uint64(ctx, value)

    def vscf_asn1wr_write_bool(self, ctx, value):
        """Write ASN.1 type: BOOLEAN.
        Return count of written bytes."""
        vscf_asn1wr_write_bool = self._lib.vscf_asn1wr_write_bool
        vscf_asn1wr_write_bool.argtypes = [POINTER(vscf_asn1wr_t), c_bool]
        vscf_asn1wr_write_bool.restype = c_size_t
        return vscf_asn1wr_write_bool(ctx, value)

    def vscf_asn1wr_write_null(self, ctx):
        """Write ASN.1 type: NULL."""
        vscf_asn1wr_write_null = self._lib.vscf_asn1wr_write_null
        vscf_asn1wr_write_null.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_write_null.restype = c_size_t
        return vscf_asn1wr_write_null(ctx)

    def vscf_asn1wr_write_octet_str(self, ctx, value):
        """Write ASN.1 type: OCTET STRING.
        Return count of written bytes."""
        vscf_asn1wr_write_octet_str = self._lib.vscf_asn1wr_write_octet_str
        vscf_asn1wr_write_octet_str.argtypes = [POINTER(vscf_asn1wr_t), vsc_data_t]
        vscf_asn1wr_write_octet_str.restype = c_size_t
        return vscf_asn1wr_write_octet_str(ctx, value)

    def vscf_asn1wr_write_octet_str_as_bitstring(self, ctx, value):
        """Write ASN.1 type: BIT STRING with all zero unused bits.

        Return count of written bytes."""
        vscf_asn1wr_write_octet_str_as_bitstring = self._lib.vscf_asn1wr_write_octet_str_as_bitstring
        vscf_asn1wr_write_octet_str_as_bitstring.argtypes = [POINTER(vscf_asn1wr_t), vsc_data_t]
        vscf_asn1wr_write_octet_str_as_bitstring.restype = c_size_t
        return vscf_asn1wr_write_octet_str_as_bitstring(ctx, value)

    def vscf_asn1wr_write_data(self, ctx, data):
        """Write raw data directly to the ASN.1 structure.
        Return count of written bytes.
        Note, use this method carefully."""
        vscf_asn1wr_write_data = self._lib.vscf_asn1wr_write_data
        vscf_asn1wr_write_data.argtypes = [POINTER(vscf_asn1wr_t), vsc_data_t]
        vscf_asn1wr_write_data.restype = c_size_t
        return vscf_asn1wr_write_data(ctx, data)

    def vscf_asn1wr_write_utf8_str(self, ctx, value):
        """Write ASN.1 type: UTF8String.
        Return count of written bytes."""
        vscf_asn1wr_write_utf8_str = self._lib.vscf_asn1wr_write_utf8_str
        vscf_asn1wr_write_utf8_str.argtypes = [POINTER(vscf_asn1wr_t), vsc_data_t]
        vscf_asn1wr_write_utf8_str.restype = c_size_t
        return vscf_asn1wr_write_utf8_str(ctx, value)

    def vscf_asn1wr_write_oid(self, ctx, value):
        """Write ASN.1 type: OID.
        Return count of written bytes."""
        vscf_asn1wr_write_oid = self._lib.vscf_asn1wr_write_oid
        vscf_asn1wr_write_oid.argtypes = [POINTER(vscf_asn1wr_t), vsc_data_t]
        vscf_asn1wr_write_oid.restype = c_size_t
        return vscf_asn1wr_write_oid(ctx, value)

    def vscf_asn1wr_write_sequence(self, ctx, len):
        """Mark previously written data of given length as ASN.1 type: SEQUENCE.
        Return count of written bytes."""
        vscf_asn1wr_write_sequence = self._lib.vscf_asn1wr_write_sequence
        vscf_asn1wr_write_sequence.argtypes = [POINTER(vscf_asn1wr_t), c_size_t]
        vscf_asn1wr_write_sequence.restype = c_size_t
        return vscf_asn1wr_write_sequence(ctx, len)

    def vscf_asn1wr_write_set(self, ctx, len):
        """Mark previously written data of given length as ASN.1 type: SET.
        Return count of written bytes."""
        vscf_asn1wr_write_set = self._lib.vscf_asn1wr_write_set
        vscf_asn1wr_write_set.argtypes = [POINTER(vscf_asn1wr_t), c_size_t]
        vscf_asn1wr_write_set.restype = c_size_t
        return vscf_asn1wr_write_set(ctx, len)

    def vscf_asn1wr_shallow_copy(self, ctx):
        vscf_asn1wr_shallow_copy = self._lib.vscf_asn1wr_shallow_copy
        vscf_asn1wr_shallow_copy.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_shallow_copy.restype = POINTER(vscf_asn1wr_t)
        return vscf_asn1wr_shallow_copy(ctx)

    def vscf_asn1wr_impl(self, ctx):
        vscf_asn1wr_impl = self._lib.vscf_asn1wr_impl
        vscf_asn1wr_impl.argtypes = [POINTER(vscf_asn1wr_t)]
        vscf_asn1wr_impl.restype = POINTER(vscf_impl_t)
        return vscf_asn1wr_impl(ctx)
