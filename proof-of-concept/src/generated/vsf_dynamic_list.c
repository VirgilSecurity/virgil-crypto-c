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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'vsf_dynamic_list_t' object management.
//  It includes:
//      - lifecycle functions;
//      - dependency management functions;
//      - RTTI functions.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_dynamic_list.h"
#include "vsf_dynamic_list_private.h"
#include "vsf_dynamic_list_list.h"
#include "vsf_impl_private.h"
//  @end


#include "vsf_list_api.h"
#include "vsf_api_private.h"


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Objects.
// ==========================================================================

//  Interface 'list' API.
static vsf_list_api_t list_api = {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'list' MUST be equal to the 'vsf_api_tag_LIST'.
    vsf_api_tag_LIST,

    //  Add item to any position
    (vsf_list_api_add_fn) vsf_dynamic_list_list_add,

    //  Add item to head
    (vsf_list_api_add_first_fn) vsf_dynamic_list_list_add_first,

    //  Add item to tail
    (vsf_list_api_add_last_fn) vsf_dynamic_list_list_add_last,

    //  Get item from specific position
    (vsf_list_api_get_fn) vsf_dynamic_list_list_get,

    //  Get item from head
    (vsf_list_api_get_first_fn) vsf_dynamic_list_list_get_first,

    //  Get item from tail
    (vsf_list_api_get_last_fn) vsf_dynamic_list_list_get_last,

    //  Get item and remove it from any position
    (vsf_list_api_remove_fn) vsf_dynamic_list_list_remove,

    //  Get and remove item from head
    (vsf_list_api_remove_first_fn) vsf_dynamic_list_list_remove_first,

    //  Get and remove item from tail
    (vsf_list_api_remove_last_fn) vsf_dynamic_list_list_remove_last,

    //  Display the items in the list as byte array
    (vsf_list_api_display_fn) vsf_dynamic_list_list_display,

    //  Display the strings in the list
    (vsf_list_api_display_strings_fn) vsf_dynamic_list_list_display_strings,
};

//  NULL terminated array of the implementaed interfaces.
//  MUST be second in the structure.
static const void * const api_array[] = {
    &list_api,
    NULL,
};

//  Compile-time known information about 'dynamic_list' implementation.
static vsf_impl_info_t impl_info = {
    //  Implementation unique identifier, MUST be first in the structure.
    vsf_impl_tag_DYNAMIC_LIST,

    //  NULL terminated array of the implementaed interfaces.
    //  MUST be second in the structure.
    api_array,

    //  Erase inner state in a secure manner.
    vsf_dynamic_list_cleanup,

    //  Self destruction, according to destruction policy.
    vsf_dynamic_list_destroy,
};


// ==========================================================================
//  Types.
// ==========================================================================

//  This type contains implementation details.
struct vsf_dynamic_list_t {
    //  Compile-time known information about this implementation.
    const vsf_impl_info_t *info;

    //  Interface implementation specific context.
    vsf_dynamic_list_context_t context;
};
typedef struct vsf_dynamic_list_t vsf_dynamic_list_t;


// ==========================================================================
//  Generated functions.
// ==========================================================================

VSF_PUBLIC void
vsf_dynamic_list_cleanup (void) {

    //TODO: Implement me.
}

VSF_PUBLIC void
vsf_dynamic_list_destroy (void) {

    //TODO: Implement me.
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
