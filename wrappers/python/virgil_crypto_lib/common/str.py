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


from ctypes import *
from ._c_bridge import VscStr
from virgil_crypto_lib.common._c_bridge import Data


class Str(object):
    """Encapsulates readonly array of characters, aka string view."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsc_str = VscStr()

    def __len__(self):
        """Return string length.

        Note, this method can be used for wrappers where direct access
        to the structure fields is prohibited."""
        result = self._lib_vsc_str.vsc_str_len(self.ctx)
        return result

    def __eq__(self, rhs):
        """Return true if given string is equal."""
        result = self._lib_vsc_str.vsc_str_equal(self.ctx, rhs)
        return result

    def is_valid_and_non_empty(self):
        """Returns true if underlying string is defined and not empty."""
        result = self._lib_vsc_str.vsc_str_is_valid_and_non_empty(self.ctx)
        return result

    def is_null_terminated(self):
        """Returns true if underlying string is null-terminated."""
        result = self._lib_vsc_str.vsc_str_is_null_terminated(self.ctx)
        return result

    def is_empty(self):
        """Returns true if underlying string is empty."""
        result = self._lib_vsc_str.vsc_str_is_empty(self.ctx)
        return result

    def icase_equal(self, rhs):
        """Return true if given string is equal (case-insensitive)."""
        result = self._lib_vsc_str.vsc_str_icase_equal(self.ctx, rhs.ctx)
        return result

    def secure_equal(self, rhs):
        """Perform constant-time string comparison.
        The time depends on the given length but not on the string itself.
        Return true if given string is equal."""
        result = self._lib_vsc_str.vsc_str_secure_equal(self.ctx, rhs.ctx)
        return result

    def is_valid(self):
        """Returns true if underlying string is defined."""
        result = self._lib_vsc_str.vsc_str_is_valid(self.ctx)
        return result

    def chars(self):
        """Returns underlying string characters.

        Note, this method can be used for wrappers where direct access
        to the structure fields is prohibited."""
        result = self._lib_vsc_str.vsc_str_chars(self.ctx)
        return result

    def as_data(self):
        """Returns underlying characters array as bytes object."""
        result = self._lib_vsc_str.vsc_str_as_data(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def slice_beg(self, offset, len):
        """Return underlying string slice starting from beginning."""
        result = self._lib_vsc_str.vsc_str_slice_beg(self.ctx, offset, len)
        return result

    def slice_end(self, offset, len):
        """Return underlying string slice starting from ending."""
        result = self._lib_vsc_str.vsc_str_slice_end(self.ctx, offset, len)
        return result

    def trim_prefix(self, prefix):
        """Return underlying string slice without given prefix."""
        result = self._lib_vsc_str.vsc_str_trim_prefix(self.ctx, prefix.ctx)
        return result
