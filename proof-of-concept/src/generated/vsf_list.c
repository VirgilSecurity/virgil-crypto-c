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


//  @description
// --------------------------------------------------------------------------
//  Provides interface to the Linked List.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_list.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Generated functions.
// ==========================================================================

//  Add item to any position
VSF_PUBLIC void
vsf_list_add (vsf_impl_t *impl, const vsf_buffer_t *item, int pos) {

    VSF_ASSERT (impl);
    VSF_ASSERT (item);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->add_cb);
    list->add_cb (impl, item, pos);
}

//  Add item to head
VSF_PUBLIC void
vsf_list_add_first (vsf_impl_t *impl, const vsf_buffer_t *item) {

    VSF_ASSERT (impl);
    VSF_ASSERT (item);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->add_first_cb);
    list->add_first_cb (impl, item);
}

//  Add item to tail
VSF_PUBLIC void
vsf_list_add_last (vsf_impl_t *impl, const vsf_buffer_t *item) {

    VSF_ASSERT (impl);
    VSF_ASSERT (item);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->add_last_cb);
    list->add_last_cb (impl, item);
}

//  Get item from specific position
VSF_PUBLIC const vsf_buffer_t *
vsf_list_get (vsf_impl_t *impl, int pos) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->get_cb);
    return list->get_cb (impl, pos);
}

//  Get item from head
VSF_PUBLIC const vsf_buffer_t *
vsf_list_get_first (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->get_first_cb);
    return list->get_first_cb (impl);
}

//  Get item from tail
VSF_PUBLIC const vsf_buffer_t *
vsf_list_get_last (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->get_last_cb);
    return list->get_last_cb (impl);
}

//  Get item and remove it from any position
VSF_PUBLIC const vsf_buffer_t *
vsf_list_remove (vsf_impl_t *impl, int pos) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->remove_cb);
    return list->remove_cb (impl, pos);
}

//  Get and remove item from head
VSF_PUBLIC const vsf_buffer_t *
vsf_list_remove_first (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->remove_first_cb);
    return list->remove_first_cb (impl);
}

//  Get and remove item from tail
VSF_PUBLIC const vsf_buffer_t *
vsf_list_remove_last (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->remove_last_cb);
    return list->remove_last_cb (impl);
}

//  Display the items in the list as byte array
VSF_PUBLIC void
vsf_list_display (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->display_cb);
    list->display_cb (impl);
}

//  Display the strings in the list
VSF_PUBLIC void
vsf_list_display_strings (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_list_api_t *list = vsf_list_api (impl);
    VSF_ASSERT (list);

    VSF_ASSERT (list->display_strings_cb);
    list->display_strings_cb (impl);
}

//  Return list API, or NULL if it is not implemented.
VSF_PUBLIC const vsf_list_api_t *
vsf_list_api (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return (vsf_list_api_t *) vsf_impl_api (impl, vsf_api_tag_LIST);
}

//  Check if given object implements interface 'list'.
VSF_PUBLIC bool
vsf_list_is_implemented (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return vsf_impl_api (impl, vsf_api_tag_LIST) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
