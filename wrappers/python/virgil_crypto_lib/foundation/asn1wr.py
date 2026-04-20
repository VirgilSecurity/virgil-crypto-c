# Copyright (C) 2015-2026 Virgil Security, Inc.
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
from ._c_bridge import VscfAsn1wr
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from .asn1_writer import Asn1Writer


class Asn1wr(Asn1Writer):
    """This is MbedTLS implementation of ASN.1 writer."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_asn1wr = VscfAsn1wr()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_asn1wr.vscf_asn1wr_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_asn1wr.vscf_asn1wr_delete(self.ctx)

    def mbedtls_has_error(self, code):
        """If given mbedtls code is equal to zero, then setup correspond error
to the context and return true, otherwise return false."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_mbedtls_has_error(self.ctx, code)
        return result

    def write_tag_data(self, data, tag):
        """Write raw data and with given tag the to ASN.1 structure."""
        d_data = Data(data)
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_tag_data(self.ctx, d_data.data, tag)
        return result

    def get_current_element_len(self, curr, end):
        """Get length of the current ASN.1 element with tag and length itself."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_get_current_element_len(curr, end)
        return result

    def swap_elements_of_set(self, to_start, to_len, from_start, from_len):
        """Swap positions of the given ASN.1 elements.
Note, "from" element must be behind "to" element.
Note, algorithm complexity is O^2."""
        self._lib_vscf_asn1wr.vscf_asn1wr_swap_elements_of_set(to_start, to_len, from_start, from_len)

    def second_element_of_set_is_less(self, first_start, first_len, second_start, second_len):
        """Return true if second element is lexicographical less then first."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_second_element_of_set_is_less(first_start, first_len, second_start, second_len)
        return result

    def sort_elements_of_set(self, len):
        """Perform lexicographical sorting of the given elements of set."""
        self._lib_vscf_asn1wr.vscf_asn1wr_sort_elements_of_set(self.ctx, len)

    def reset(self, out, out_len):
        """Reset all internal states and prepare to new ASN.1 writing operations."""
        self._lib_vscf_asn1wr.vscf_asn1wr_reset(self.ctx, out, out_len)

    def finish(self, do_not_adjust):
        """Finalize writing and forbid further operations.

Note, that ASN.1 structure is always written to the buffer end, and
if argument "do not adjust" is false, then data is moved to the
beginning, otherwise - data is left at the buffer end.

Returns length of the written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_finish(self.ctx, do_not_adjust)
        return result

    def bytes(self):
        """Returns pointer to the inner buffer."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_bytes(self.ctx)
        return result

    def len(self):
        """Returns total inner buffer length."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_len(self.ctx)
        return result

    def written_len(self):
        """Returns how many bytes were already written to the ASN.1 structure."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_written_len(self.ctx)
        return result

    def unwritten_len(self):
        """Returns how many bytes are available for writing."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_unwritten_len(self.ctx)
        return result

    def has_error(self):
        """Return true if status is not "success"."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_has_error(self.ctx)
        return result

    def status(self):
        """Return error code."""
        status = self._lib_vscf_asn1wr.vscf_asn1wr_status(self.ctx)
        VscfStatus.handle_status(status)

    def reserve(self, len):
        """Move writing position backward for the given length.
Return current writing position."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_reserve(self.ctx, len)
        return result

    def write_tag(self, tag):
        """Write ASN.1 tag.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_tag(self.ctx, tag)
        return result

    def write_context_tag(self, tag, len):
        """Write context-specific ASN.1 tag.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_context_tag(self.ctx, tag, len)
        return result

    def write_len(self, len):
        """Write length of the following data.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_len(self.ctx, len)
        return result

    def write_int(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_int(self.ctx, value)
        return result

    def write_int8(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_int8(self.ctx, value)
        return result

    def write_int16(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_int16(self.ctx, value)
        return result

    def write_int32(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_int32(self.ctx, value)
        return result

    def write_int64(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_int64(self.ctx, value)
        return result

    def write_uint(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_uint(self.ctx, value)
        return result

    def write_uint8(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_uint8(self.ctx, value)
        return result

    def write_uint16(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_uint16(self.ctx, value)
        return result

    def write_uint32(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_uint32(self.ctx, value)
        return result

    def write_uint64(self, value):
        """Write ASN.1 type: INTEGER.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_uint64(self.ctx, value)
        return result

    def write_bool(self, value):
        """Write ASN.1 type: BOOLEAN.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_bool(self.ctx, value)
        return result

    def write_null(self):
        """Write ASN.1 type: NULL."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_null(self.ctx)
        return result

    def write_octet_str(self, value):
        """Write ASN.1 type: OCTET STRING.
Return count of written bytes."""
        d_value = Data(value)
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_octet_str(self.ctx, d_value.data)
        return result

    def write_octet_str_as_bitstring(self, value):
        """Write ASN.1 type: BIT STRING with all zero unused bits.

Return count of written bytes."""
        d_value = Data(value)
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_octet_str_as_bitstring(self.ctx, d_value.data)
        return result

    def write_data(self, data):
        """Write raw data directly to the ASN.1 structure.
Return count of written bytes.
Note, use this method carefully."""
        d_data = Data(data)
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_data(self.ctx, d_data.data)
        return result

    def write_utf8_str(self, value):
        """Write ASN.1 type: UTF8String.
Return count of written bytes."""
        d_value = Data(value)
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_utf8_str(self.ctx, d_value.data)
        return result

    def write_oid(self, value):
        """Write ASN.1 type: OID.
Return count of written bytes."""
        d_value = Data(value)
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_oid(self.ctx, d_value.data)
        return result

    def write_sequence(self, len):
        """Mark previously written data of given length as ASN.1 type: SEQUENCE.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_sequence(self.ctx, len)
        return result

    def write_set(self, len):
        """Mark previously written data of given length as ASN.1 type: SET.
Return count of written bytes."""
        result = self._lib_vscf_asn1wr.vscf_asn1wr_write_set(self.ctx, len)
        return result

    def __len__(self):
        return self.len()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_asn1wr = VscfAsn1wr()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_asn1wr = VscfAsn1wr()
        inst.ctx = inst._lib_vscf_asn1wr.vscf_asn1wr_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_asn1wr.vscf_asn1wr_shallow_copy(value)
        self._c_impl = self._lib_vscf_asn1wr.vscf_asn1wr_impl(self.ctx)
