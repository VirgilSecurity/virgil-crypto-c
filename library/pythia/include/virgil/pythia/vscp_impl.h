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
//  This module contains common functionality for all 'implementation' object.
//  It is also enumerate all available implementations within crypto libary.
// --------------------------------------------------------------------------

#ifndef VSCP_IMPL_H_INCLUDED
#define VSCP_IMPL_H_INCLUDED

#include "vscp_library.h"
#include "vscp_error.h"
#include "vscp_api.h"
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
enum vscp_impl_tag_t {
    vscp_impl_tag_BEGIN = 0,
    vscp_impl_tag_END
};
typedef enum vscp_impl_tag_t vscp_impl_tag_t;

//
//  Generic type for any 'implementation'.
//
typedef struct vscp_impl_t vscp_impl_t;

//
//  Callback type for cleanup action.
//
typedef void (*vscp_impl_cleanup_fn)(vscp_impl_t *impl);

//
//  Callback type for delete action.
//
typedef void (*vscp_impl_delete_fn)(vscp_impl_t *impl);

//
//  Return 'API' object that is fulfiled with a meta information
//  specific to the given implementation object.
//  Or NULL if object does not implement requested 'API'.
//
VSCP_PUBLIC const vscp_api_t *
vscp_impl_api(vscp_impl_t *impl, vscp_api_tag_t api_tag);

//
//  Return unique 'Implementation TAG'.
//
VSCP_PUBLIC vscp_impl_tag_t
vscp_impl_tag(vscp_impl_t *impl);

//
//  Cleanup implementation object and it's dependencies.
//
VSCP_PUBLIC void
vscp_impl_cleanup(vscp_impl_t *impl);

//
//  Delete implementation object and it's dependencies.
//
VSCP_PUBLIC void
vscp_impl_delete(vscp_impl_t *impl);

//
//  Destroy implementation object and it's dependencies.
//
VSCP_PUBLIC void
vscp_impl_destroy(vscp_impl_t **impl_ref);

//
//  Copy implementation object by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCP_PUBLIC vscp_impl_t *
vscp_impl_copy(vscp_impl_t *impl);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCP_IMPL_H_INCLUDED
//  @end
