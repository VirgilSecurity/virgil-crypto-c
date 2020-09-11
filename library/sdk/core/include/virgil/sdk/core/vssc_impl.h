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
//  This module contains common functionality for all 'implementation' object.
//  It is also enumerate all available implementations within crypto libary.
// --------------------------------------------------------------------------

#ifndef VSSC_IMPL_H_INCLUDED
#define VSSC_IMPL_H_INCLUDED

#include "vssc_library.h"
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
//  Enumerates all possible implementations within crypto library.
//
enum vssc_impl_tag_t {
    vssc_impl_tag_BEGIN = 0,
    vssc_impl_tag_HTTP_CLIENT_CURL,
    vssc_impl_tag_END
};
#ifndef VSSC_IMPL_TAG_T_DEFINED
#define VSSC_IMPL_TAG_T_DEFINED
    typedef enum vssc_impl_tag_t vssc_impl_tag_t;
#endif // VSSC_IMPL_TAG_T_DEFINED

//
//  Generic type for any 'implementation'.
//
#ifndef VSSC_IMPL_T_DEFINED
#define VSSC_IMPL_T_DEFINED
    typedef struct vssc_impl_t vssc_impl_t;
#endif // VSSC_IMPL_T_DEFINED

//
//  Return 'API' object that is fulfiled with a meta information
//  specific to the given implementation object.
//  Or NULL if object does not implement requested 'API'.
//
VSSC_PUBLIC const vssc_api_t *
vssc_impl_api(const vssc_impl_t *impl, vssc_api_tag_t api_tag);

//
//  Return unique 'Implementation TAG'.
//
VSSC_PUBLIC vssc_impl_tag_t
vssc_impl_tag(const vssc_impl_t *impl);

//
//  Cleanup implementation object and it's dependencies.
//
VSSC_PUBLIC void
vssc_impl_cleanup(vssc_impl_t *impl);

//
//  Delete implementation object and it's dependencies.
//
VSSC_PUBLIC void
vssc_impl_delete(const vssc_impl_t *impl);

//
//  Destroy implementation object and it's dependencies.
//
VSSC_PUBLIC void
vssc_impl_destroy(vssc_impl_t **impl_ref);

//
//  Copy implementation object by increasing reference counter.
//
VSSC_PUBLIC vssc_impl_t *
vssc_impl_shallow_copy(vssc_impl_t *impl);

//
//  Copy implementation object by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_impl_t *
vssc_impl_shallow_copy_const(const vssc_impl_t *impl);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_IMPL_H_INCLUDED
//  @end
