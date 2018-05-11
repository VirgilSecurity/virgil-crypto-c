//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#ifndef VSF_IMPL_PRIVATE_H_INCLUDED
#define VSF_IMPL_PRIVATE_H_INCLUDED

#include "vsf_library.h"
#include "vsf_impl.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Contains common properties for any 'API' implementation object.
//
struct vsf_impl_info_t {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_t impl_tag;
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    const vsf_api_t** api_array;
    //
    //  Erase inner state in a secure manner.
    //
    vsf_impl_cleanup_fn self_cleanup_cb;
    //
    //  Self destruction, according to destruction policy.
    //
    vsf_impl_destroy_fn self_destroy_cb;
};
typedef struct vsf_impl_info_t vsf_impl_info_t;

//
//  Contains header of any 'API' implementation structure.
//  It is used for runtime type casting and checking.
//
struct vsf_impl_t {
    //
    //  Compile-time known information.
    //
    const vsf_impl_info_t* info;
};


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_IMPL_PRIVATE_H_INCLUDED
//  @end
