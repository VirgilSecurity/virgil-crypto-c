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
//  Light version of the class "str buffer".
//
//  Note, this class always handles a null-terminated string.
//  Note, this class might be used to store copied strings within objects.
//  Note, this class' ownership can not be retained.
//  Note, this class can not be used as part of any public interface.
// --------------------------------------------------------------------------

#ifndef VSC_STR_MUTABLE_H_INCLUDED
#define VSC_STR_MUTABLE_H_INCLUDED

#include "vsc_library.h"
#include "vsc_str.h"

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
//  Handle 'str mutable' context.
//
#ifndef VSC_STR_MUTABLE_T_DEFINED
#define VSC_STR_MUTABLE_T_DEFINED
    typedef struct vsc_str_mutable_t vsc_str_mutable_t;
#endif // VSC_STR_MUTABLE_T_DEFINED
struct vsc_str_mutable_t {
    //
    //  Underlying characters array.
    //
    char *chars;
    //
    //  Characters array length.
    //
    size_t len;
};

//
//  Return size of 'vsc_str_mutable_t'.
//
VSC_PUBLIC size_t
vsc_str_mutable_ctx_size(void);

//
//  Create a mutable string by copying a given string.
//
VSC_PUBLIC vsc_str_mutable_t
vsc_str_mutable_from_str(vsc_str_t str);

//
//  Create a mutable string by concatenating 2 strings.
//
VSC_PUBLIC vsc_str_mutable_t
vsc_str_mutable_concat(vsc_str_t lhs, vsc_str_t rhs);

//
//  Returns true if underlying string is defined.
//
VSC_PUBLIC bool
vsc_str_mutable_is_valid(vsc_str_mutable_t self);

//
//  Returns immutable str.
//
VSC_PUBLIC vsc_str_t
vsc_str_mutable_as_str(vsc_str_mutable_t self);

//
//  Init underlying structure.
//
VSC_PUBLIC void
vsc_str_mutable_init(vsc_str_mutable_t *self);

//
//  Deallocate underlying string.
//
VSC_PUBLIC void
vsc_str_mutable_release(vsc_str_mutable_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSC_STR_MUTABLE_H_INCLUDED
//  @end
