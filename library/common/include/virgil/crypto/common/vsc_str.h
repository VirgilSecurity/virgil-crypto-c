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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Encapsulates readonly array of characters, aka string view.
// --------------------------------------------------------------------------

#ifndef VSC_STR_H_INCLUDED
#define VSC_STR_H_INCLUDED

#include "vsc_library.h"
#include "vsc_str.h"
#include "vsc_data.h"

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'str' context.
//
typedef struct vsc_str_t vsc_str_t;
struct vsc_str_t {
    //
    //  Underlying characters array.
    //
    vsc_data_t data;
};

//
//  Return size of 'vsc_str_t'.
//
VSC_PUBLIC size_t
vsc_str_ctx_size(void);

//
//  Create string.
//
VSC_PUBLIC vsc_str_t
vsc_str(const char *str, size_t len);

//
//  Create an empty string.
//
VSC_PUBLIC vsc_str_t
vsc_str_empty(void);

//
//  Returns true if underlying string is defined.
//
VSC_PUBLIC bool
vsc_str_is_valid(vsc_str_t self);

//
//  Returns true if underlying string is empty.
//
VSC_PUBLIC bool
vsc_str_is_empty(vsc_str_t self);

//
//  Return true if given string is equal.
//
VSC_PUBLIC bool
vsc_str_equal(vsc_str_t self, vsc_str_t rhs);

//
//  Return string length.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC size_t
vsc_str_len(vsc_str_t self);

//
//  Returns underlying string characters.
//
//  Note, this method can be used for wrappers where direct access
//  to the structure fields is prohibited.
//
VSC_PUBLIC const char *
vsc_str_chars(vsc_str_t self);

//
//  Perform constant-time string comparison.
//  The time depends on the given length but not on the string itself.
//  Return true if given string is equal.
//
VSC_PUBLIC bool
vsc_str_secure_equal(vsc_str_t self, vsc_str_t rhs);

//
//  Return underlying string slice starting from beginning.
//
VSC_PUBLIC vsc_str_t
vsc_str_slice_beg(vsc_str_t self, size_t offset, size_t len);

//
//  Return underlying string slice starting from ending.
//
VSC_PUBLIC vsc_str_t
vsc_str_slice_end(vsc_str_t self, size_t offset, size_t len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSC_STR_H_INCLUDED
//  @end
