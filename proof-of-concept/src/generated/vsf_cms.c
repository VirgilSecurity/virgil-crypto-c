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
//  Provides interface to the CMS functionallity.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_cms.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Generated functions.
// ==========================================================================

//  Read CMS data.
VSF_PUBLIC int
vsf_cms_read (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_cms_api_t *cms = vsf_cms_api (impl);
    VSF_ASSERT (cms);

    VSF_ASSERT (cms->read_cb);
    return cms->read_cb (impl);
}

//  Write CMS data.
VSF_PUBLIC int
vsf_cms_write (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_cms_api_t *cms = vsf_cms_api (impl);
    VSF_ASSERT (cms);

    VSF_ASSERT (cms->write_cb);
    return cms->write_cb (impl);
}

//  Return cms API, or NULL if it is not implemented.
VSF_PUBLIC const vsf_cms_api_t *
vsf_cms_api (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return (vsf_cms_api_t *) vsf_impl_api (impl, vsf_api_tag_CMS);
}

//  Check if given object implements interface 'cms'.
VSF_PUBLIC bool
vsf_cms_is_implemented (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return vsf_impl_api (impl, vsf_api_tag_CMS) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
