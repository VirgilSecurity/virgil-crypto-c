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
from abc import *


class Asn1Writer(object):
    """Provides interface to the ASN.1 writer.
    Note, elements are written starting from the buffer ending.
    Note, that all "write" methods move writing position backward."""
    __metaclass__ = ABCMeta

    @abstractmethod
    def reset(self, out, out_len):
        """Reset all internal states and prepare to new ASN.1 writing operations."""
        raise NotImplementedError()

    @abstractmethod
    def finish(self, do_not_adjust):
        """Finalize writing and forbid further operations.

        Note, that ASN.1 structure is always written to the buffer end, and
        if argument "do not adjust" is false, then data is moved to the
        beginning, otherwise - data is left at the buffer end.

        Returns length of the written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def __bytes__(self):
        """Returns pointer to the inner buffer."""
        raise NotImplementedError()

    @abstractmethod
    def __len__(self):
        """Returns total inner buffer length."""
        raise NotImplementedError()

    @abstractmethod
    def written_len(self):
        """Returns how many bytes were already written to the ASN.1 structure."""
        raise NotImplementedError()

    @abstractmethod
    def unwritten_len(self):
        """Returns how many bytes are available for writing."""
        raise NotImplementedError()

    @abstractmethod
    def has_error(self):
        """Return true if status is not "success"."""
        raise NotImplementedError()

    @abstractmethod
    def status(self):
        """Return error code."""
        raise NotImplementedError()

    @abstractmethod
    def reserve(self, len):
        """Move writing position backward for the given length.
        Return current writing position."""
        raise NotImplementedError()

    @abstractmethod
    def write_tag(self, tag):
        """Write ASN.1 tag.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_context_tag(self, tag, len):
        """Write context-specific ASN.1 tag.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_len(self, len):
        """Write length of the following data.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_int(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_int8(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_int16(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_int32(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_int64(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_uint(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_uint8(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_uint16(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_uint32(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_uint64(self, value):
        """Write ASN.1 type: INTEGER.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_bool(self, value):
        """Write ASN.1 type: BOOLEAN.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_null(self):
        """Write ASN.1 type: NULL."""
        raise NotImplementedError()

    @abstractmethod
    def write_octet_str(self, value):
        """Write ASN.1 type: OCTET STRING.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_octet_str_as_bitstring(self, value):
        """Write ASN.1 type: BIT STRING with all zero unused bits.

        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_data(self, data):
        """Write raw data directly to the ASN.1 structure.
        Return count of written bytes.
        Note, use this method carefully."""
        raise NotImplementedError()

    @abstractmethod
    def write_utf8_str(self, value):
        """Write ASN.1 type: UTF8String.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_oid(self, value):
        """Write ASN.1 type: OID.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_sequence(self, len):
        """Mark previously written data of given length as ASN.1 type: SEQUENCE.
        Return count of written bytes."""
        raise NotImplementedError()

    @abstractmethod
    def write_set(self, len):
        """Mark previously written data of given length as ASN.1 type: SET.
        Return count of written bytes."""
        raise NotImplementedError()
