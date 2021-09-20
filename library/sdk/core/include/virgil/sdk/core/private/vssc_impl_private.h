//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
//  This module contains Private API common for all 'implementation' objects.
// --------------------------------------------------------------------------

#ifndef VSSC_IMPL_PRIVATE_H_INCLUDED
#define VSSC_IMPL_PRIVATE_H_INCLUDED

#include "vssc_library.h"
#include "vssc_impl.h"
#include "vssc_atomic.h"
#include "vssc_api.h"

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
//  Callback type for cleanup action.
//
typedef void (*vssc_impl_cleanup_fn)(vssc_impl_t *impl);

//
//  Callback type for delete action.
//
typedef void (*vssc_impl_delete_fn)(vssc_impl_t *impl);

//
//  Returns API of the requested interface if implemented,
//  otherwise - NULL.
//
typedef const vssc_api_t * (*vssc_impl_find_api_fn)(vssc_api_tag_t api_tag);

//
//  Contains common properties for any 'API' implementation object.
//
#ifndef VSSC_IMPL_INFO_T_DEFINED
#define VSSC_IMPL_INFO_T_DEFINED
    typedef struct vssc_impl_info_t vssc_impl_info_t;
#endif // VSSC_IMPL_INFO_T_DEFINED
struct vssc_impl_info_t {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vssc_impl_tag_t impl_tag;
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vssc_impl_find_api_fn find_api_cb;
    //
    //  Release acquired inner resources.
    //
    vssc_impl_cleanup_fn self_cleanup_cb;
    //
    //  Self destruction, according to destruction policy.
    //
    vssc_impl_delete_fn self_delete_cb;
};

//
//  Contains header of any 'API' implementation structure.
//  It is used for runtime type casting and checking.
//
struct vssc_impl_t {
    //
    //  Compile-time known information.
    //
    const vssc_impl_info_t *info;
    //
    //  Reference counter.
    //
    VSSC_ATOMIC size_t refcnt;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_IMPL_PRIVATE_H_INCLUDED
//  @end
