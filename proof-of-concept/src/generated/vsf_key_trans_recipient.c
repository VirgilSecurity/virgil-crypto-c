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
//  This module contains 'vsf_key_trans_recipient_t' object management.
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

#include "vsf_key_trans_recipient.h"
#include "vsf_key_trans_recipient_private.h"
#include "vsf_key_trans_recipient_cms.h"
#include "vsf_impl_private.h"
//  @end

#include "vsf_cms_api.h"

//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Objects.
// ==========================================================================

//  Interface 'cms' API.
static vsf_cms_api_t cms_api = {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cms' MUST be equal to the 'vsf_api_tag_CMS'.
    vsf_api_tag_CMS,

    //  Read CMS data.
    (vsf_cms_api_read_fn) vsf_key_trans_recipient_cms_read,

    //  Write CMS data.
    (vsf_cms_api_write_fn) vsf_key_trans_recipient_cms_write,
};

//  NULL terminated array of the implementaed interfaces.
//  MUST be second in the structure.
static const void * const api_array[] = {
    &cms_api,
    NULL,
};

//  Compile-time known information about 'key_trans_recipient' implementation.
static vsf_impl_info_t impl_info = {
    //  Implementation unique identifier, MUST be first in the structure.
    vsf_impl_tag_KEY_TRANS_RECIPIENT,

    //  NULL terminated array of the implementaed interfaces.
    //  MUST be second in the structure.
    api_array,

    //  Erase inner state in a secure manner.
    vsf_key_trans_recipient_cleanup,

    //  Self destruction, according to destruction policy.
    vsf_key_trans_recipient_destroy,
};


// ==========================================================================
//  Types.
// ==========================================================================

//  This type contains implementation details.
struct vsf_key_trans_recipient_t {
    //  Compile-time known information about this implementation.
    const vsf_impl_info_t *info;

    //  Interface implementation specific context.
    vsf_key_trans_recipient_context_t context;
};
typedef struct vsf_key_trans_recipient_t vsf_key_trans_recipient_t;


// ==========================================================================
//  Generated functions.
// ==========================================================================

VSF_PUBLIC void
vsf_key_trans_recipient_cleanup (void) {

    //TODO: Implement me.
}

VSF_PUBLIC void
vsf_key_trans_recipient_destroy (void) {

    //TODO: Implement me.
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
