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
//  Light version of the class "str buffer".
//
//  Note, this class always handles a null-terminated string.
//  Note, this class might be used to store copied strings within objects.
//  Note, this class' ownership can not be retained.
//  Note, this class can not be used as part of any public interface.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsc_str_mutable.h"
#include "vsc_memory.h"
#include "vsc_assert.h"

#include <ctype.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return size of 'vsc_str_mutable_t'.
//
VSC_PUBLIC size_t
vsc_str_mutable_ctx_size(void) {

    return sizeof(vsc_str_mutable_t);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Create a mutable string by copying a given string.
//
VSC_PUBLIC vsc_str_mutable_t
vsc_str_mutable_from_str(vsc_str_t str) {

    VSC_ASSERT(vsc_str_is_valid(str));

    char *chars_copy = vsc_alloc(str.len + 1);
    VSC_ASSERT_ALLOC(chars_copy);

    memcpy(chars_copy, str.chars, str.len);
    chars_copy[str.len] = '\0';

    return (vsc_str_mutable_t){chars_copy, str.len};
}

//
//  Create a mutable string by converting a given string to lower case.
//
VSC_PUBLIC vsc_str_mutable_t
vsc_str_mutable_lowercase_from_str(vsc_str_t str) {

    VSC_ASSERT(vsc_str_is_valid(str));

    char *chars_copy = vsc_alloc(str.len + 1);
    VSC_ASSERT_ALLOC(chars_copy);

    for (size_t pos = 0; pos < str.len; ++pos) {
        chars_copy[pos] = (char)tolower(str.chars[pos]);
    }

    chars_copy[str.len] = '\0';

    return (vsc_str_mutable_t){chars_copy, str.len};
}

//
//  Create a mutable string by concatenating 2 strings.
//
VSC_PUBLIC vsc_str_mutable_t
vsc_str_mutable_concat(vsc_str_t lhs, vsc_str_t rhs) {

    VSC_ASSERT(vsc_str_is_valid(lhs));
    VSC_ASSERT(vsc_str_is_valid(rhs));

    const size_t chars_len = lhs.len + rhs.len;
    char *chars_copy = vsc_alloc(chars_len + 1);
    VSC_ASSERT_ALLOC(chars_copy);

    memcpy(chars_copy, lhs.chars, lhs.len);
    memcpy(chars_copy + lhs.len, rhs.chars, rhs.len);
    chars_copy[chars_len] = '\0';

    return (vsc_str_mutable_t){chars_copy, chars_len};
}

//
//  Create a mutable string by concatenating 2 strings separated with a space.
//
VSC_PUBLIC vsc_str_mutable_t
vsc_str_mutable_concat_with_space_sep(vsc_str_t lhs, vsc_str_t rhs) {

    VSC_ASSERT(vsc_str_is_valid(lhs));
    VSC_ASSERT(vsc_str_is_valid(rhs));

    const size_t chars_len = lhs.len + 1 /* space */ + rhs.len;
    char *chars_copy = vsc_alloc(chars_len + 1);
    VSC_ASSERT_ALLOC(chars_copy);

    memcpy(chars_copy, lhs.chars, lhs.len);
    chars_copy[lhs.len] = ' ';
    memcpy(chars_copy + lhs.len + 1, rhs.chars, rhs.len);
    chars_copy[chars_len] = '\0';

    return (vsc_str_mutable_t){chars_copy, chars_len};
}

//
//  Returns true if underlying string is defined.
//
VSC_PUBLIC bool
vsc_str_mutable_is_valid(vsc_str_mutable_t self) {

    return self.chars != NULL;
}

//
//  Returns immutable str.
//
VSC_PUBLIC vsc_str_t
vsc_str_mutable_as_str(vsc_str_mutable_t self) {

    VSC_ASSERT(vsc_str_mutable_is_valid(self));

    return vsc_str(self.chars, self.len);
}

//
//  Returns immutable str as bytes.
//
VSC_PUBLIC vsc_data_t
vsc_str_mutable_as_data(vsc_str_mutable_t self) {

    VSC_ASSERT(vsc_str_mutable_is_valid(self));

    return vsc_data((const byte *)self.chars, self.len);
}

//
//  Init underlying structure.
//
VSC_PUBLIC void
vsc_str_mutable_init(vsc_str_mutable_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_erase(self, sizeof(vsc_str_mutable_t));
}

//
//  Deallocate underlying string.
//
VSC_PUBLIC void
vsc_str_mutable_release(vsc_str_mutable_t *self) {

    if (NULL == self || NULL == self->chars) {
        return;
    }

    vsc_dealloc(self->chars);
    vsc_erase(self, sizeof(vsc_str_mutable_t));
}
