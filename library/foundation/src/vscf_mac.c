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
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Provides interface to the stateless MAC (message authentication code) algorithms.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mac.h"
#include "vscf_assert.h"
#include "vscf_mac_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Calculate MAC over given data.
//
VSCF_PUBLIC void
vscf_mac(const vscf_mac_api_t *mac_api, vsc_data_t key, vsc_data_t data, vsc_buffer_t *mac) {

    VSCF_ASSERT_PTR (mac_api);

    VSCF_ASSERT_PTR (mac_api->mac_cb);
    mac_api->mac_cb (key, data, mac);
}

//
//  Return mac API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_mac_api_t *
vscf_mac_api(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_MAC);
    return (const vscf_mac_api_t *) api;
}

//
//  Return mac info API.
//
VSCF_PUBLIC const vscf_mac_info_api_t *
vscf_mac_mac_info_api(const vscf_mac_api_t *mac_api) {

    VSCF_ASSERT_PTR (mac_api);

    return mac_api->mac_info_api;
}

//
//  Check if given object implements interface 'mac'.
//
VSCF_PUBLIC bool
vscf_mac_is_implemented(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_MAC) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_mac_api_tag(const vscf_mac_api_t *mac_api) {

    VSCF_ASSERT_PTR (mac_api);

    return mac_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_mac_impl_tag(const vscf_mac_api_t *mac_api) {

    VSCF_ASSERT_PTR (mac_api);

    return mac_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
