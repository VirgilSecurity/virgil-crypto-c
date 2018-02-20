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
//  Interface 'list' API.
// --------------------------------------------------------------------------

#ifndef VSF_LIST_API_H_INCLUDED
#define VSF_LIST_API_H_INCLUDED

#include "vsf_library.h"
#include "vsf_api.h"
#include "vsf_impl.h"
//  @end


#include "vsf_buffer_api.h"

#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Full defined types.
// ==========================================================================

//  Add item to any position
typedef void (*vsf_list_api_add_fn) (vsf_impl_t *impl, const vsf_buffer_t *item, int pos);

//  Add item to head
typedef void (*vsf_list_api_add_first_fn) (vsf_impl_t *impl, const vsf_buffer_t *item);

//  Add item to tail
typedef void (*vsf_list_api_add_last_fn) (vsf_impl_t *impl, const vsf_buffer_t *item);

//  Get item from specific position
typedef const vsf_buffer_t * (*vsf_list_api_get_fn) (vsf_impl_t *impl, int pos);

//  Get item from head
typedef const vsf_buffer_t * (*vsf_list_api_get_first_fn) (vsf_impl_t *impl);

//  Get item from tail
typedef const vsf_buffer_t * (*vsf_list_api_get_last_fn) (vsf_impl_t *impl);

//  Get item and remove it from any position
typedef const vsf_buffer_t * (*vsf_list_api_remove_fn) (vsf_impl_t *impl, int pos);

//  Get and remove item from head
typedef const vsf_buffer_t * (*vsf_list_api_remove_first_fn) (vsf_impl_t *impl);

//  Get and remove item from tail
typedef const vsf_buffer_t * (*vsf_list_api_remove_last_fn) (vsf_impl_t *impl);

//  Display the items in the list as byte array
typedef void (*vsf_list_api_display_fn) (vsf_impl_t *impl);

//  Display the strings in the list
typedef void (*vsf_list_api_display_strings_fn) (vsf_impl_t *impl);

//  Interface 'list' API.
struct vsf_list_api_t {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'list' MUST be equal to the 'vsf_api_tag_LIST'.
    vsf_api_tag_t api_tag;

    //  Add item to any position
    void (*add_cb) (vsf_impl_t *impl, const vsf_buffer_t *item, int pos);

    //  Add item to head
    void (*add_first_cb) (vsf_impl_t *impl, const vsf_buffer_t *item);

    //  Add item to tail
    void (*add_last_cb) (vsf_impl_t *impl, const vsf_buffer_t *item);

    //  Get item from specific position
    const vsf_buffer_t * (*get_cb) (vsf_impl_t *impl, int pos);

    //  Get item from head
    const vsf_buffer_t * (*get_first_cb) (vsf_impl_t *impl);

    //  Get item from tail
    const vsf_buffer_t * (*get_last_cb) (vsf_impl_t *impl);

    //  Get item and remove it from any position
    const vsf_buffer_t * (*remove_cb) (vsf_impl_t *impl, int pos);

    //  Get and remove item from head
    const vsf_buffer_t * (*remove_first_cb) (vsf_impl_t *impl);

    //  Get and remove item from tail
    const vsf_buffer_t * (*remove_last_cb) (vsf_impl_t *impl);

    //  Display the items in the list as byte array
    void (*display_cb) (vsf_impl_t *impl);

    //  Display the strings in the list
    void (*display_strings_cb) (vsf_impl_t *impl);
};
typedef struct vsf_list_api_t vsf_list_api_t;


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_LIST_API_H_INCLUDED
//  @end
