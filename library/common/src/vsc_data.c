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
//  Encapsulates fixed byte array.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsc_data.h"
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
//  Byte array that is used as "empty array" mark.
//
static const byte empty_data[] = {
    0x00
};

//
//  Return size of 'vsc_data_t'.
//
VSC_PUBLIC size_t
vsc_data_ctx_size(void) {

    return sizeof(vsc_data_t);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Creates data from the preallocated bytes.
//
VSC_PUBLIC vsc_data_t
vsc_data(const byte *bytes, size_t len) {

    VSC_ASSERT_PTR(bytes);

    return (vsc_data_t){bytes, len};
}

//
//  Creates data from the preallocated string.
//
VSC_PUBLIC vsc_data_t
vsc_data_from_str(const char *str, size_t len) {

    VSC_ASSERT_PTR(str);

    return (vsc_data_t){(const byte *)str, len};
}

//
//  Creates empty data.
//
VSC_PUBLIC vsc_data_t
vsc_data_empty(void) {

    return (vsc_data_t){empty_data, 0};
}

//
//  Returns true if underlying byte array is defined.
//
VSC_PUBLIC bool
vsc_data_is_valid(vsc_data_t self) {

    return self.bytes != NULL;
}

//
//  Returns true if underlying byte array contains only zeros.
//
VSC_PUBLIC bool
vsc_data_is_zero(vsc_data_t self) {

    VSC_ASSERT(vsc_data_is_valid(self));

    for (size_t pos = 0; pos < self.len; ++pos) {
        if (self.bytes[pos] != 0) {
            return false;
        }
    }

    return true;
}

//
//  Returns true if underlying byte array is empty.
//
VSC_PUBLIC bool
vsc_data_is_empty(vsc_data_t self) {

    return 0 == self.len;
}

//
//  Return true if given data are equal.
//
VSC_PUBLIC bool
vsc_data_equal(vsc_data_t self, vsc_data_t rhs) {

    VSC_ASSERT(vsc_data_is_valid(self));
    VSC_ASSERT(vsc_data_is_valid(rhs));

    if (self.len != rhs.len) {
        return false;
    }

    bool is_equal = memcmp(self.bytes, rhs.bytes, rhs.len) == 0;
    return is_equal;
}

//
//  Return data length.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC size_t
vsc_data_len(vsc_data_t self) {

    VSC_ASSERT(vsc_data_is_valid(self));

    return self.len;
}

//
//  Returns underlying data bytes.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC const byte *
vsc_data_bytes(vsc_data_t self) {

    VSC_ASSERT(vsc_data_is_valid(self));

    return self.bytes;
}

//
//  Perform constant-time data comparison.
//  The time depends on the given length but not on the data itself.
//  Return true if given data are equal.
//
VSC_PUBLIC bool
vsc_data_secure_equal(vsc_data_t self, vsc_data_t rhs) {

    VSC_ASSERT(vsc_data_is_valid(self));
    VSC_ASSERT(vsc_data_is_valid(rhs));

    if (self.len != rhs.len) {
        return false;
    }

    bool is_equal = vsc_memory_secure_equal(self.bytes, rhs.bytes, rhs.len);
    return is_equal;
}

//
//  Return underlying data slice starting from beginning.
//
VSC_PUBLIC vsc_data_t
vsc_data_slice_beg(vsc_data_t self, size_t offset, size_t len) {

    VSC_ASSERT(vsc_data_is_valid(self));
    VSC_ASSERT(self.len >= offset + len);

    return (vsc_data_t){self.bytes + offset, len};
}

//
//  Return underlying data slice starting from ending.
//
VSC_PUBLIC vsc_data_t
vsc_data_slice_end(vsc_data_t self, size_t offset, size_t len) {

    VSC_ASSERT(vsc_data_is_valid(self));
    VSC_ASSERT(self.len >= offset + len);

    return (vsc_data_t){self.bytes + self.len - offset - len, len};
}
