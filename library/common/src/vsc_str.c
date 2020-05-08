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

    vsc_str_t self;

    self.data = vsc_data_from_str(str, len);

    return self;
}

//
//  Create an empty string.
//
VSC_PUBLIC vsc_str_t
vsc_str_empty(void) {

    vsc_str_t self;

    self.data = vsc_data_empty();

    return self;
}

//
//  Returns true if underlying string is defined.
//
VSC_PUBLIC bool
vsc_str_is_valid(vsc_str_t self) {

    return vsc_data_is_valid(self.data);
}

//
//  Returns true if underlying string is empty.
//
VSC_PUBLIC bool
vsc_str_is_empty(vsc_str_t self) {

    return vsc_data_is_empty(self.data);
}

//
//  Return true if given string is equal.
//
VSC_PUBLIC bool
vsc_str_equal(vsc_str_t self, vsc_str_t rhs) {

    return vsc_data_equal(self.data, rhs.data);
}

//
//  Return string length.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC size_t
vsc_str_len(vsc_str_t self) {

    return vsc_data_len(self.data);
}

//
//  Returns underlying string characters.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC const char *
vsc_str_chars(vsc_str_t self) {

    return (const char *)vsc_data_bytes(self.data);
}

//
//  Perform constant-time string comparison.
//  The time depends on the given length but not on the string itself.
//  Return true if given string is equal.
//
VSC_PUBLIC bool
vsc_str_secure_equal(vsc_str_t self, vsc_str_t rhs) {

    return vsc_data_secure_equal(self.data, rhs.data);
}

//
//  Return underlying string slice starting from beginning.
//
VSC_PUBLIC vsc_str_t
vsc_str_slice_beg(vsc_str_t self, size_t offset, size_t len) {

    vsc_str_t slice;

    slice.data = vsc_data_slice_beg(self.data, offset, len);

    return slice;
}

//
//  Return underlying string slice starting from ending.
//
VSC_PUBLIC vsc_str_t
vsc_str_slice_end(vsc_str_t self, size_t offset, size_t len) {

    vsc_str_t slice;

    slice.data = vsc_data_slice_end(self.data, offset, len);

    return slice;
}
