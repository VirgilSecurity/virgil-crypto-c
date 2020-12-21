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
from ._vsc_str import vsc_str_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vsc_str_buffer_t(Structure):
    pass


class VscStrBuffer(object):
    """Encapsulates fixed characters array with variable effective length."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.common

    def vsc_str_buffer_new(self):
        vsc_str_buffer_new = self._lib.vsc_str_buffer_new
        vsc_str_buffer_new.argtypes = []
        vsc_str_buffer_new.restype = POINTER(vsc_str_buffer_t)
        return vsc_str_buffer_new()

    def vsc_str_buffer_delete(self, ctx):
        vsc_str_buffer_delete = self._lib.vsc_str_buffer_delete
        vsc_str_buffer_delete.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_delete.restype = None
        return vsc_str_buffer_delete(ctx)

    def vsc_str_buffer_new_with_capacity(self, capacity):
        """Allocate inner character buffer of given capacity."""
        vsc_str_buffer_new_with_capacity = self._lib.vsc_str_buffer_new_with_capacity
        vsc_str_buffer_new_with_capacity.argtypes = [c_size_t]
        vsc_str_buffer_new_with_capacity.restype = POINTER(vsc_str_buffer_t)
        return vsc_str_buffer_new_with_capacity(capacity)

    def vsc_str_buffer_new_with_str(self, str):
        """Allocate inner character buffer as copy of given string."""
        vsc_str_buffer_new_with_str = self._lib.vsc_str_buffer_new_with_str
        vsc_str_buffer_new_with_str.argtypes = [vsc_str_t]
        vsc_str_buffer_new_with_str.restype = POINTER(vsc_str_buffer_t)
        return vsc_str_buffer_new_with_str(str)

    def vsc_str_buffer_is_empty(self, ctx):
        """Returns true if string length is zero."""
        vsc_str_buffer_is_empty = self._lib.vsc_str_buffer_is_empty
        vsc_str_buffer_is_empty.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_is_empty.restype = c_bool
        return vsc_str_buffer_is_empty(ctx)

    def vsc_str_buffer_equal(self, ctx, rhs):
        """Return true if strings are equal."""
        vsc_str_buffer_equal = self._lib.vsc_str_buffer_equal
        vsc_str_buffer_equal.argtypes = [POINTER(vsc_str_buffer_t), POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_equal.restype = c_bool
        return vsc_str_buffer_equal(ctx, rhs)

    def vsc_str_buffer_secure_equal(self, ctx, rhs):
        """Perform constant-time string comparison.
        The time depends on the string length but not on the characters.
        Return true if strings are equal."""
        vsc_str_buffer_secure_equal = self._lib.vsc_str_buffer_secure_equal
        vsc_str_buffer_secure_equal.argtypes = [POINTER(vsc_str_buffer_t), POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_secure_equal.restype = c_bool
        return vsc_str_buffer_secure_equal(ctx, rhs)

    def vsc_str_buffer_alloc(self, ctx, capacity):
        """Allocates inner characters array with a given capacity.
        Precondition: characters array is initialized.
        Precondition: characters array does not hold any character.
        Postcondition: inner characters array is allocated."""
        vsc_str_buffer_alloc = self._lib.vsc_str_buffer_alloc
        vsc_str_buffer_alloc.argtypes = [POINTER(vsc_str_buffer_t), c_size_t]
        vsc_str_buffer_alloc.restype = None
        return vsc_str_buffer_alloc(ctx, capacity)

    def vsc_str_buffer_release(self, ctx):
        """Release inner characters array."""
        vsc_str_buffer_release = self._lib.vsc_str_buffer_release
        vsc_str_buffer_release.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_release.restype = None
        return vsc_str_buffer_release(ctx)

    def vsc_str_buffer_use(self, ctx, chars, chars_len):
        """Use given characters array as underlying string buffer.
        Precondition: buffer is initialized.
        Precondition: buffer does not hold any characters array.
        Note, caller is responsible for given characters array deallocation."""
        vsc_str_buffer_use = self._lib.vsc_str_buffer_use
        vsc_str_buffer_use.argtypes = [POINTER(vsc_str_buffer_t), POINTER(POINTER(c_char)), c_size_t]
        vsc_str_buffer_use.restype = None
        return vsc_str_buffer_use(ctx, chars, chars_len)

    def vsc_str_buffer_take(self, ctx, chars, chars_len, dealloc):
        """Take given characters array as underlying string buffer.
        Precondition: buffer is initialized.
        Precondition: buffer does not hold any characters array.
        Note, this class is responsible for given characters array deallocation."""
        vsc_str_buffer_take = self._lib.vsc_str_buffer_take
        vsc_str_buffer_take.argtypes = [POINTER(vsc_str_buffer_t), POINTER(POINTER(c_char)), c_size_t, Unknown]
        vsc_str_buffer_take.restype = None
        return vsc_str_buffer_take(ctx, chars, chars_len, dealloc)

    def vsc_str_buffer_make_secure(self, ctx):
        """Mark string buffer as it holds sensitive data that must be erased
        in a secure manner during destruction."""
        vsc_str_buffer_make_secure = self._lib.vsc_str_buffer_make_secure
        vsc_str_buffer_make_secure.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_make_secure.restype = None
        return vsc_str_buffer_make_secure(ctx)

    def vsc_str_buffer_is_full(self, ctx):
        """Returns true if string buffer is full."""
        vsc_str_buffer_is_full = self._lib.vsc_str_buffer_is_full
        vsc_str_buffer_is_full.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_is_full.restype = c_bool
        return vsc_str_buffer_is_full(ctx)

    def vsc_str_buffer_is_valid(self, ctx):
        """Returns true if string buffer is configured and has valid internal states."""
        vsc_str_buffer_is_valid = self._lib.vsc_str_buffer_is_valid
        vsc_str_buffer_is_valid.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_is_valid.restype = c_bool
        return vsc_str_buffer_is_valid(ctx)

    def vsc_str_buffer_chars(self, ctx):
        """Returns underlying characters array."""
        vsc_str_buffer_chars = self._lib.vsc_str_buffer_chars
        vsc_str_buffer_chars.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_chars.restype = POINTER(POINTER(c_char))
        return vsc_str_buffer_chars(ctx)

    def vsc_str_buffer_str(self, ctx):
        """Returns underlying string buffer characters as string."""
        vsc_str_buffer_str = self._lib.vsc_str_buffer_str
        vsc_str_buffer_str.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_str.restype = vsc_str_t
        return vsc_str_buffer_str(ctx)

    def vsc_str_buffer_data(self, ctx):
        """Returns underlying string buffer characters as data."""
        vsc_str_buffer_data = self._lib.vsc_str_buffer_data
        vsc_str_buffer_data.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_data.restype = vsc_data_t
        return vsc_str_buffer_data(ctx)

    def vsc_str_buffer_capacity(self, ctx):
        """Returns string buffer capacity."""
        vsc_str_buffer_capacity = self._lib.vsc_str_buffer_capacity
        vsc_str_buffer_capacity.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_capacity.restype = c_size_t
        return vsc_str_buffer_capacity(ctx)

    def vsc_str_buffer_len(self, ctx):
        """Returns string buffer effective length - length of characters that are actually used."""
        vsc_str_buffer_len = self._lib.vsc_str_buffer_len
        vsc_str_buffer_len.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_len.restype = c_size_t
        return vsc_str_buffer_len(ctx)

    def vsc_str_buffer_unused_len(self, ctx):
        """Returns length of the characters array that are not in use yet."""
        vsc_str_buffer_unused_len = self._lib.vsc_str_buffer_unused_len
        vsc_str_buffer_unused_len.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_unused_len.restype = c_size_t
        return vsc_str_buffer_unused_len(ctx)

    def vsc_str_buffer_begin(self, ctx):
        """Returns writable pointer to the string buffer first element."""
        vsc_str_buffer_begin = self._lib.vsc_str_buffer_begin
        vsc_str_buffer_begin.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_begin.restype = POINTER(POINTER(c_char))
        return vsc_str_buffer_begin(ctx)

    def vsc_str_buffer_unused_chars(self, ctx):
        """Returns pointer to the first unused character in the string buffer."""
        vsc_str_buffer_unused_chars = self._lib.vsc_str_buffer_unused_chars
        vsc_str_buffer_unused_chars.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_unused_chars.restype = POINTER(POINTER(c_char))
        return vsc_str_buffer_unused_chars(ctx)

    def vsc_str_buffer_inc_used(self, ctx, len):
        """Increase used characters by given length."""
        vsc_str_buffer_inc_used = self._lib.vsc_str_buffer_inc_used
        vsc_str_buffer_inc_used.argtypes = [POINTER(vsc_str_buffer_t), c_size_t]
        vsc_str_buffer_inc_used.restype = None
        return vsc_str_buffer_inc_used(ctx, len)

    def vsc_str_buffer_dec_used(self, ctx, len):
        """Decrease used characters by given length."""
        vsc_str_buffer_dec_used = self._lib.vsc_str_buffer_dec_used
        vsc_str_buffer_dec_used.argtypes = [POINTER(vsc_str_buffer_t), c_size_t]
        vsc_str_buffer_dec_used.restype = None
        return vsc_str_buffer_dec_used(ctx, len)

    def vsc_str_buffer_write_char(self, ctx, ch):
        """Copy char to the string buffer."""
        vsc_str_buffer_write_char = self._lib.vsc_str_buffer_write_char
        vsc_str_buffer_write_char.argtypes = [POINTER(vsc_str_buffer_t), c_char]
        vsc_str_buffer_write_char.restype = None
        return vsc_str_buffer_write_char(ctx, ch)

    def vsc_str_buffer_write_str(self, ctx, str):
        """Copy string to the string buffer."""
        vsc_str_buffer_write_str = self._lib.vsc_str_buffer_write_str
        vsc_str_buffer_write_str.argtypes = [POINTER(vsc_str_buffer_t), vsc_str_t]
        vsc_str_buffer_write_str.restype = None
        return vsc_str_buffer_write_str(ctx, str)

    def vsc_str_buffer_append_char(self, ctx, ch):
        """Append char to the string buffer and reallocate if needed by coping.

        Precondition: string buffer should be an owner of the underlying characters array.

        Note, this operation can be slow if copy operation occurred.
        Note, string buffer capacity is doubled."""
        vsc_str_buffer_append_char = self._lib.vsc_str_buffer_append_char
        vsc_str_buffer_append_char.argtypes = [POINTER(vsc_str_buffer_t), c_char]
        vsc_str_buffer_append_char.restype = None
        return vsc_str_buffer_append_char(ctx, ch)

    def vsc_str_buffer_append_str(self, ctx, str):
        """Copy string to the string buffer and reallocate if needed by coping.

        Precondition: string buffer should be an owner of the underlying characters array.

        Note, this operation can be slow if copy operation occurred.
        Note, string buffer capacity is doubled."""
        vsc_str_buffer_append_str = self._lib.vsc_str_buffer_append_str
        vsc_str_buffer_append_str.argtypes = [POINTER(vsc_str_buffer_t), vsc_str_t]
        vsc_str_buffer_append_str.restype = None
        return vsc_str_buffer_append_str(ctx, str)

    def vsc_str_buffer_make_null_terminated(self, ctx):
        """Write a null-termination character without increasing length.

        Precondition: "unused len" must be at least 1."""
        vsc_str_buffer_make_null_terminated = self._lib.vsc_str_buffer_make_null_terminated
        vsc_str_buffer_make_null_terminated.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_make_null_terminated.restype = None
        return vsc_str_buffer_make_null_terminated(ctx)

    def vsc_str_buffer_replace_char(self, ctx, char_old, char_new):
        """Replace all occurrences of one character to another character."""
        vsc_str_buffer_replace_char = self._lib.vsc_str_buffer_replace_char
        vsc_str_buffer_replace_char.argtypes = [POINTER(vsc_str_buffer_t), c_char, c_char]
        vsc_str_buffer_replace_char.restype = None
        return vsc_str_buffer_replace_char(ctx, char_old, char_new)

    def vsc_str_buffer_rtrim(self, ctx, char_to_trim):
        """Remove all occurrences of given character from the string end."""
        vsc_str_buffer_rtrim = self._lib.vsc_str_buffer_rtrim
        vsc_str_buffer_rtrim.argtypes = [POINTER(vsc_str_buffer_t), c_char]
        vsc_str_buffer_rtrim.restype = None
        return vsc_str_buffer_rtrim(ctx, char_to_trim)

    def vsc_str_buffer_reset_with_capacity(self, ctx, min_capacity):
        """Reset strung buffer and increase capacity if given value less then current."""
        vsc_str_buffer_reset_with_capacity = self._lib.vsc_str_buffer_reset_with_capacity
        vsc_str_buffer_reset_with_capacity.argtypes = [POINTER(vsc_str_buffer_t), c_size_t]
        vsc_str_buffer_reset_with_capacity.restype = None
        return vsc_str_buffer_reset_with_capacity(ctx, min_capacity)

    def vsc_str_buffer_reset(self, ctx):
        """Reset to the initial state.
        After reset underlying characters array can be re-used."""
        vsc_str_buffer_reset = self._lib.vsc_str_buffer_reset
        vsc_str_buffer_reset.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_reset.restype = None
        return vsc_str_buffer_reset(ctx)

    def vsc_str_buffer_erase(self, ctx):
        """Zeroing output buffer in secure manner.
        And reset it to the initial state."""
        vsc_str_buffer_erase = self._lib.vsc_str_buffer_erase
        vsc_str_buffer_erase.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_erase.restype = None
        return vsc_str_buffer_erase(ctx)

    def vsc_str_buffer_shallow_copy(self, ctx):
        vsc_str_buffer_shallow_copy = self._lib.vsc_str_buffer_shallow_copy
        vsc_str_buffer_shallow_copy.argtypes = [POINTER(vsc_str_buffer_t)]
        vsc_str_buffer_shallow_copy.restype = POINTER(vsc_str_buffer_t)
        return vsc_str_buffer_shallow_copy(ctx)
