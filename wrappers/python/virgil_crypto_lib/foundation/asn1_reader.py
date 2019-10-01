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


class Asn1Reader(object):
    """Provides interface to the ASN.1 reader.
    Note, that all "read" methods move reading position forward.
    Note, that all "get" do not change reading position."""
    __metaclass__ = ABCMeta

    @abstractmethod
    def reset(self, data):
        """Reset all internal states and prepare to new ASN.1 reading operations."""
        raise NotImplementedError()

    @abstractmethod
    def left_len(self):
        """Return length in bytes how many bytes are left for reading."""
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
    def get_tag(self):
        """Get tag of the current ASN.1 element."""
        raise NotImplementedError()

    @abstractmethod
    def get_len(self):
        """Get length of the current ASN.1 element."""
        raise NotImplementedError()

    @abstractmethod
    def get_data_len(self):
        """Get length of the current ASN.1 element with tag and length itself."""
        raise NotImplementedError()

    @abstractmethod
    def read_tag(self, tag):
        """Read ASN.1 type: TAG.
        Return element length."""
        raise NotImplementedError()

    @abstractmethod
    def read_context_tag(self, tag):
        """Read ASN.1 type: context-specific TAG.
        Return element length.
        Return 0 if current position do not points to the requested tag."""
        raise NotImplementedError()

    @abstractmethod
    def read_int(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_int8(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_int16(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_int32(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_int64(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_uint(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_uint8(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_uint16(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_uint32(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_uint64(self):
        """Read ASN.1 type: INTEGER."""
        raise NotImplementedError()

    @abstractmethod
    def read_bool(self):
        """Read ASN.1 type: BOOLEAN."""
        raise NotImplementedError()

    @abstractmethod
    def read_null(self):
        """Read ASN.1 type: NULL."""
        raise NotImplementedError()

    @abstractmethod
    def read_null_optional(self):
        """Read ASN.1 type: NULL, only if it exists.
        Note, this method is safe to call even no more data is left for reading."""
        raise NotImplementedError()

    @abstractmethod
    def read_octet_str(self):
        """Read ASN.1 type: OCTET STRING."""
        raise NotImplementedError()

    @abstractmethod
    def read_bitstring_as_octet_str(self):
        """Read ASN.1 type: BIT STRING."""
        raise NotImplementedError()

    @abstractmethod
    def read_utf8_str(self):
        """Read ASN.1 type: UTF8String."""
        raise NotImplementedError()

    @abstractmethod
    def read_oid(self):
        """Read ASN.1 type: OID."""
        raise NotImplementedError()

    @abstractmethod
    def read_data(self, len):
        """Read raw data of given length."""
        raise NotImplementedError()

    @abstractmethod
    def read_sequence(self):
        """Read ASN.1 type: SEQUENCE.
        Return element length."""
        raise NotImplementedError()

    @abstractmethod
    def read_set(self):
        """Read ASN.1 type: SET.
        Return element length."""
        raise NotImplementedError()
