//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
//  Encapsulates fixed byte array.
// --------------------------------------------------------------------------

#ifndef VSC_DATA_H_INCLUDED
#define VSC_DATA_H_INCLUDED

#include "vsc_library.h"
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
//  Handle 'data' context.
//
typedef struct vsc_data_t vsc_data_t;
struct vsc_data_t {
    //
    //  Underlying byte array.
    //
    const byte *bytes;
    //
    //  Byte array length.
    //
    size_t len;
};

//
//  Return size of 'vsc_data_t'.
//
VSC_PUBLIC size_t
vsc_data_ctx_size(void);

//
//  Creates data from the preallocated bytes.
//
VSC_PUBLIC vsc_data_t
vsc_data(const byte *bytes, size_t len);

//
//  Creates data from the preallocated string.
//
VSC_PUBLIC vsc_data_t
vsc_data_from_str(const char *str, size_t len);

//
//  Creates empty data.
//
VSC_PUBLIC vsc_data_t
vsc_data_empty(void);

//
//  Returns true if underlying byte array is defined.
//
VSC_PUBLIC bool
vsc_data_is_valid(vsc_data_t data);

//
//  Returns true if underlying byte array contains only zeros.
//
VSC_PUBLIC bool
vsc_data_is_zero(vsc_data_t data);

//
//  Returns true if underlying byte array is empty.
//
VSC_PUBLIC bool
vsc_data_is_empty(vsc_data_t data);

//
//  Return true if given datas are equal.
//
VSC_PUBLIC bool
vsc_data_equal(vsc_data_t data, vsc_data_t rhs);

//
//  Return underlying data slice starting from beginning.
//
VSC_PUBLIC vsc_data_t
vsc_data_slice_beg(vsc_data_t data, size_t offset, size_t len);

//
//  Return underlying data slice starting from ending.
//
VSC_PUBLIC vsc_data_t
vsc_data_slice_end(vsc_data_t data, size_t offset, size_t len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSC_DATA_H_INCLUDED
//  @end
