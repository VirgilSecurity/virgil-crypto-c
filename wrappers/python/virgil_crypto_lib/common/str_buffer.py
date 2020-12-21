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
from ._c_bridge import VscStrBuffer
from virgil_crypto_lib.common._c_bridge import Data


class StrBuffer(object):
    """Encapsulates fixed characters array with variable effective length."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsc_str_buffer = VscStrBuffer()
        self.ctx = self._lib_vsc_str_buffer.vsc_str_buffer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsc_str_buffer.vsc_str_buffer_delete(self.ctx)

    @classmethod
    def with_capacity(cls, capacity):
        """Allocate inner character buffer of given capacity."""
        inst = cls.__new__(cls)
        inst._lib_vsc_str_buffer = VscStrBuffer()
        inst.ctx = inst._lib_vsc_str_buffer.vsc_str_buffer_new_with_capacity(capacity)
        return inst

    @classmethod
    def with_str(cls, str):
        """Allocate inner character buffer as copy of given string."""
        inst = cls.__new__(cls)
        inst._lib_vsc_str_buffer = VscStrBuffer()
        inst.ctx = inst._lib_vsc_str_buffer.vsc_str_buffer_new_with_str(str)
        return inst

    def __len__(self):
        """Returns string buffer effective length - length of characters that are actually used."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_len(self.ctx)
        return result

    def __eq__(self, rhs):
        """Return true if strings are equal."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_equal(self.ctx, rhs)
        return result

    def secure_equal(self, rhs):
        """Perform constant-time string comparison.
        The time depends on the string length but not on the characters.
        Return true if strings are equal."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_secure_equal(self.ctx, rhs.ctx)
        return result

    def alloc(self, capacity):
        """Allocates inner characters array with a given capacity.
        Precondition: characters array is initialized.
        Precondition: characters array does not hold any character.
        Postcondition: inner characters array is allocated."""
        self._lib_vsc_str_buffer.vsc_str_buffer_alloc(self.ctx, capacity)

    def is_empty(self):
        """Returns true if string length is zero."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_is_empty(self.ctx)
        return result

    def use(self, chars, chars_len):
        """Use given characters array as underlying string buffer.
        Precondition: buffer is initialized.
        Precondition: buffer does not hold any characters array.
        Note, caller is responsible for given characters array deallocation."""
        self._lib_vsc_str_buffer.vsc_str_buffer_use(self.ctx, chars, chars_len)

    def take(self, chars, chars_len, dealloc):
        """Take given characters array as underlying string buffer.
        Precondition: buffer is initialized.
        Precondition: buffer does not hold any characters array.
        Note, this class is responsible for given characters array deallocation."""
        self._lib_vsc_str_buffer.vsc_str_buffer_take(self.ctx, chars, chars_len, dealloc)

    def make_secure(self):
        """Mark string buffer as it holds sensitive data that must be erased
        in a secure manner during destruction."""
        self._lib_vsc_str_buffer.vsc_str_buffer_make_secure(self.ctx)

    def is_full(self):
        """Returns true if string buffer is full."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_is_full(self.ctx)
        return result

    def is_valid(self):
        """Returns true if string buffer is configured and has valid internal states."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_is_valid(self.ctx)
        return result

    def chars(self):
        """Returns underlying characters array."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_chars(self.ctx)
        return result

    def str(self):
        """Returns underlying string buffer characters as string."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_str(self.ctx)
        return result

    def data(self):
        """Returns underlying string buffer characters as data."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_data(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def capacity(self):
        """Returns string buffer capacity."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_capacity(self.ctx)
        return result

    def release(self):
        """Release inner characters array."""
        self._lib_vsc_str_buffer.vsc_str_buffer_release(self.ctx)

    def unused_len(self):
        """Returns length of the characters array that are not in use yet."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_unused_len(self.ctx)
        return result

    def begin(self):
        """Returns writable pointer to the string buffer first element."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_begin(self.ctx)
        return result

    def unused_chars(self):
        """Returns pointer to the first unused character in the string buffer."""
        result = self._lib_vsc_str_buffer.vsc_str_buffer_unused_chars(self.ctx)
        return result

    def inc_used(self, len):
        """Increase used characters by given length."""
        self._lib_vsc_str_buffer.vsc_str_buffer_inc_used(self.ctx, len)

    def dec_used(self, len):
        """Decrease used characters by given length."""
        self._lib_vsc_str_buffer.vsc_str_buffer_dec_used(self.ctx, len)

    def write_char(self, ch):
        """Copy char to the string buffer."""
        self._lib_vsc_str_buffer.vsc_str_buffer_write_char(self.ctx, ch)

    def write_str(self, str):
        """Copy string to the string buffer."""
        self._lib_vsc_str_buffer.vsc_str_buffer_write_str(self.ctx, str.ctx)

    def append_char(self, ch):
        """Append char to the string buffer and reallocate if needed by coping.

        Precondition: string buffer should be an owner of the underlying characters array.

        Note, this operation can be slow if copy operation occurred.
        Note, string buffer capacity is doubled."""
        self._lib_vsc_str_buffer.vsc_str_buffer_append_char(self.ctx, ch)

    def append_str(self, str):
        """Copy string to the string buffer and reallocate if needed by coping.

        Precondition: string buffer should be an owner of the underlying characters array.

        Note, this operation can be slow if copy operation occurred.
        Note, string buffer capacity is doubled."""
        self._lib_vsc_str_buffer.vsc_str_buffer_append_str(self.ctx, str.ctx)

    def make_null_terminated(self):
        """Write a null-termination character without increasing length.

        Precondition: "unused len" must be at least 1."""
        self._lib_vsc_str_buffer.vsc_str_buffer_make_null_terminated(self.ctx)

    def replace_char(self, char_old, char_new):
        """Replace all occurrences of one character to another character."""
        self._lib_vsc_str_buffer.vsc_str_buffer_replace_char(self.ctx, char_old, char_new)

    def rtrim(self, char_to_trim):
        """Remove all occurrences of given character from the string end."""
        self._lib_vsc_str_buffer.vsc_str_buffer_rtrim(self.ctx, char_to_trim)

    def reset_with_capacity(self, min_capacity):
        """Reset strung buffer and increase capacity if given value less then current."""
        self._lib_vsc_str_buffer.vsc_str_buffer_reset_with_capacity(self.ctx, min_capacity)

    def reset(self):
        """Reset to the initial state.
        After reset underlying characters array can be re-used."""
        self._lib_vsc_str_buffer.vsc_str_buffer_reset(self.ctx)

    def erase(self):
        """Zeroing output buffer in secure manner.
        And reset it to the initial state."""
        self._lib_vsc_str_buffer.vsc_str_buffer_erase(self.ctx)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsc_str_buffer = VscStrBuffer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsc_str_buffer = VscStrBuffer()
        inst.ctx = inst._lib_vsc_str_buffer.vsc_str_buffer_shallow_copy(c_ctx)
        return inst
