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


from virgil_crypto_lib._libs import *
from ctypes import *
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vsc_str_t(Structure):
    _fields_ = [
        ("chars", char),
        ("len", size)
    ]


class VscStr(object):
    """Encapsulates readonly array of characters, aka string view."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.common

    def vsc_str_is_valid(self, ctx):
        """Returns true if underlying string is defined."""
        vsc_str_is_valid = self._lib.vsc_str_is_valid
        vsc_str_is_valid.argtypes = [POINTER(vsc_str_t)]
        vsc_str_is_valid.restype = c_bool
        return vsc_str_is_valid(ctx)

    def vsc_str_is_empty(self, ctx):
        """Returns true if underlying string is empty."""
        vsc_str_is_empty = self._lib.vsc_str_is_empty
        vsc_str_is_empty.argtypes = [POINTER(vsc_str_t)]
        vsc_str_is_empty.restype = c_bool
        return vsc_str_is_empty(ctx)

    def vsc_str_is_valid_and_non_empty(self, ctx):
        """Returns true if underlying string is defined and not empty."""
        vsc_str_is_valid_and_non_empty = self._lib.vsc_str_is_valid_and_non_empty
        vsc_str_is_valid_and_non_empty.argtypes = [POINTER(vsc_str_t)]
        vsc_str_is_valid_and_non_empty.restype = c_bool
        return vsc_str_is_valid_and_non_empty(ctx)

    def vsc_str_is_null_terminated(self, ctx):
        """Returns true if underlying string is null-terminated."""
        vsc_str_is_null_terminated = self._lib.vsc_str_is_null_terminated
        vsc_str_is_null_terminated.argtypes = [POINTER(vsc_str_t)]
        vsc_str_is_null_terminated.restype = c_bool
        return vsc_str_is_null_terminated(ctx)

    def vsc_str_equal(self, ctx, rhs):
        """Return true if given string is equal."""
        vsc_str_equal = self._lib.vsc_str_equal
        vsc_str_equal.argtypes = [POINTER(vsc_str_t), vsc_str_t]
        vsc_str_equal.restype = c_bool
        return vsc_str_equal(ctx, rhs)

    def vsc_str_icase_equal(self, ctx, rhs):
        """Return true if given string is equal (case-insensitive)."""
        vsc_str_icase_equal = self._lib.vsc_str_icase_equal
        vsc_str_icase_equal.argtypes = [POINTER(vsc_str_t), vsc_str_t]
        vsc_str_icase_equal.restype = c_bool
        return vsc_str_icase_equal(ctx, rhs)

    def vsc_str_secure_equal(self, ctx, rhs):
        """Perform constant-time string comparison.
        The time depends on the given length but not on the string itself.
        Return true if given string is equal."""
        vsc_str_secure_equal = self._lib.vsc_str_secure_equal
        vsc_str_secure_equal.argtypes = [POINTER(vsc_str_t), vsc_str_t]
        vsc_str_secure_equal.restype = c_bool
        return vsc_str_secure_equal(ctx, rhs)

    def vsc_str_len(self, ctx):
        """Return string length.

        Note, this method can be used for wrappers where direct access
        to the structure fields is prohibited."""
        vsc_str_len = self._lib.vsc_str_len
        vsc_str_len.argtypes = [POINTER(vsc_str_t)]
        vsc_str_len.restype = c_size_t
        return vsc_str_len(ctx)

    def vsc_str_chars(self, ctx):
        """Returns underlying string characters.

        Note, this method can be used for wrappers where direct access
        to the structure fields is prohibited."""
        vsc_str_chars = self._lib.vsc_str_chars
        vsc_str_chars.argtypes = [POINTER(vsc_str_t)]
        vsc_str_chars.restype = POINTER(POINTER(c_char))
        return vsc_str_chars(ctx)

    def vsc_str_as_data(self, ctx):
        """Returns underlying characters array as bytes object."""
        vsc_str_as_data = self._lib.vsc_str_as_data
        vsc_str_as_data.argtypes = [POINTER(vsc_str_t)]
        vsc_str_as_data.restype = vsc_data_t
        return vsc_str_as_data(ctx)

    def vsc_str_slice_beg(self, ctx, offset, len):
        """Return underlying string slice starting from beginning."""
        vsc_str_slice_beg = self._lib.vsc_str_slice_beg
        vsc_str_slice_beg.argtypes = [POINTER(vsc_str_t), c_size_t, c_size_t]
        vsc_str_slice_beg.restype = vsc_str_t
        return vsc_str_slice_beg(ctx, offset, len)

    def vsc_str_slice_end(self, ctx, offset, len):
        """Return underlying string slice starting from ending."""
        vsc_str_slice_end = self._lib.vsc_str_slice_end
        vsc_str_slice_end.argtypes = [POINTER(vsc_str_t), c_size_t, c_size_t]
        vsc_str_slice_end.restype = vsc_str_t
        return vsc_str_slice_end(ctx, offset, len)

    def vsc_str_trim_prefix(self, ctx, prefix):
        """Return underlying string slice without given prefix."""
        vsc_str_trim_prefix = self._lib.vsc_str_trim_prefix
        vsc_str_trim_prefix.argtypes = [POINTER(vsc_str_t), vsc_str_t]
        vsc_str_trim_prefix.restype = vsc_str_t
        return vsc_str_trim_prefix(ctx, prefix)
