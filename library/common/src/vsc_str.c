//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Encapsulates readonly array of characters, aka string view.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsc_str.h"
#include "vsc_memory.h"
#include "vsc_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return size of 'vsc_str_t'.
//
VSC_PUBLIC size_t
vsc_str_ctx_size(void) {

    return sizeof(vsc_str_t);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Create string.
//
VSC_PUBLIC vsc_str_t
vsc_str(const char *str, size_t len) {

    return (vsc_str_t){str, len};
}

//
//  Create string from data.
//
VSC_PRIVATE vsc_str_t
vsc_str_from_data(vsc_data_t data) {

    return vsc_str((const char *)data.bytes, data.len);
}

//
//  Create an empty string.
//
VSC_PUBLIC vsc_str_t
vsc_str_empty(void) {

    return vsc_str("", 0);
}

//
//  Returns true if underlying string is defined.
//
VSC_PUBLIC bool
vsc_str_is_valid(vsc_str_t self) {

    return self.chars != NULL;
}

//
//  Returns true if underlying string is empty.
//
VSC_PUBLIC bool
vsc_str_is_empty(vsc_str_t self) {

    return 0 == self.len;
}

//
//  Return true if given string is equal.
//
VSC_PUBLIC bool
vsc_str_equal(vsc_str_t self, vsc_str_t rhs) {

    return vsc_data_equal(vsc_str_as_data(self), vsc_str_as_data(rhs));
}

//
//  Perform constant-time string comparison.
//  The time depends on the given length but not on the string itself.
//  Return true if given string is equal.
//
VSC_PUBLIC bool
vsc_str_secure_equal(vsc_str_t self, vsc_str_t rhs) {

    VSC_ASSERT(vsc_str_is_valid(self));
    VSC_ASSERT(vsc_str_is_valid(rhs));

    return vsc_data_secure_equal(vsc_str_as_data(self), vsc_str_as_data(rhs));
}

//
//  Return string length.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC size_t
vsc_str_len(vsc_str_t self) {

    return self.len;
}

//
//  Returns underlying string characters.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC const char *
vsc_str_chars(vsc_str_t self) {

    VSC_ASSERT(vsc_str_is_valid(self));

    return self.chars;
}

//
//  Returns underlying characters array as bytes object.
//
VSC_PUBLIC vsc_data_t
vsc_str_as_data(vsc_str_t self) {

    VSC_ASSERT(vsc_str_is_valid(self));

    return vsc_data_from_str(self.chars, self.len);
}

//
//  Return underlying string slice starting from beginning.
//
VSC_PUBLIC vsc_str_t
vsc_str_slice_beg(vsc_str_t self, size_t offset, size_t len) {

    VSC_ASSERT(vsc_str_is_valid(self));
    VSC_ASSERT(self.len >= offset + len);

    return (vsc_str_t){self.chars + offset, len};
}

//
//  Return underlying string slice starting from ending.
//
VSC_PUBLIC vsc_str_t
vsc_str_slice_end(vsc_str_t self, size_t offset, size_t len) {

    VSC_ASSERT(vsc_str_is_valid(self));
    VSC_ASSERT(self.len >= offset + len);

    return (vsc_str_t){self.chars + self.len - offset - len, len};
}

//
//  Return underlying string slice without given prefix.
//
VSC_PUBLIC vsc_str_t
vsc_str_trim_prefix(vsc_str_t self, vsc_str_t prefix) {

    VSC_ASSERT(vsc_str_is_valid(self));
    VSC_ASSERT(vsc_str_is_valid(prefix));

    if (0 == prefix.len || 0 == self.len || prefix.len > self.len) {
        return self;
    }

    const char *self_chars = self.chars;
    const char *prefix_chars = prefix.chars;
    size_t prefix_len = prefix.len + 1;

    while (--prefix_len != 0 && *self_chars++ == *prefix_chars++) {
    }

    if (prefix_len != 0) {
        return self;
    }

    return vsc_str(self_chars, (size_t)(self.len - prefix.len));
}
