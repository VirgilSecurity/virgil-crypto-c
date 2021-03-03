# Copyright (C) 2015-2020 Virgil Security, Inc.
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


import base64
import binascii
import datetime
import json
import sys

from ctypes import *

if sys.version_info[0] == 2:
    from __builtin__ import unicode

    def normalize_string(data_str):
        if isinstance(data_str, unicode):
            return bytearray(data_str, "utf-8")

    def check_unicode(source):
        return isinstance(source, unicode)
else:
    def normalize_string(data_str):
        return data_str

    def check_unicode(source):
        return False


class Utils(object):

    @staticmethod
    def b64_decode(source):
        """Decode base64, padding being optional.

        Args:
            source: Base64 data as an ASCII byte string

        Returns:
            The decoded byte string.

        """
        try:
            if isinstance(source, bytes):
                return base64.urlsafe_b64decode(source)
            return base64.urlsafe_b64decode(bytearray(source, "utf-8"))
        except (binascii.Error, TypeError) as e:
            missing_padding = len(source) % 4
            if missing_padding != 0:
                if isinstance(source, str) or isinstance(source, unicode):
                    source += '=' * (4 - missing_padding)
                if isinstance(source, bytes) or isinstance(source, bytearray):
                    source += b'=' * (4 - missing_padding)
            if isinstance(source, bytes):
                return base64.urlsafe_b64decode(source)
            return base64.urlsafe_b64decode(bytearray(source, "utf-8"))

    @staticmethod
    def b64_encode(source):
        """
        Removes any `=` used as padding from the encoded string.

        Args:
            Data for encoding.

        Returns:
            Encoded data without '=' sign
        """
        if isinstance(source, bytes):
            encoded = base64.urlsafe_b64encode(source)
        else:
            encoded = base64.urlsafe_b64encode(bytearray(source, "utf-8"))
        return bytearray(encoded).decode().rstrip("=")

    @staticmethod
    def strtobytes(source):
        # type: (str) -> Tuple[*int]
        """Convert string to bytes tuple used for all crypto methods."""
        return tuple(bytearray(source.encode()))

    @classmethod
    def b64tobytes(cls, source):
        # type: (str) -> Tuple[*int]
        """Convert source to bytearray and encode using base64."""
        return cls.strtobytes(cls.b64decode(source))

    @staticmethod
    def b64encode(source):
        # type: (Union[str, bytes]) -> str
        