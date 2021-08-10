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


//  @description
// --------------------------------------------------------------------------
//  Provides interface to the key derivation function (KDF) algorithms
//  that use salt and teration count.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_salted_kdf.h"
#include "vscf_salted_kdf_api.h"
#include "vscf_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Prepare algorithm to derive new key.
//
VSCF_PUBLIC void
vscf_salted_kdf_reset(vscf_impl_t *impl, vsc_data_t salt, size_t iteration_count) {

    const vscf_salted_kdf_api_t *salted_kdf_api = vscf_salted_kdf_api(impl);
    VSCF_ASSERT_PTR (salted_kdf_api);

    VSCF_ASSERT_PTR (salted_kdf_api->reset_cb);
    salted_kdf_api->reset_cb (impl, salt, iteration_count);
}

//
//  Setup application specific information (optional).
//  Can be empty.
//
VSCF_PUBLIC void
vscf_salted_kdf_set_info(vscf_impl_t *impl, vsc_data_t info) {

    const vscf_salted_kdf_api_t *salted_kdf_api = vscf_salted_kdf_api(impl);
    VSCF_ASSERT_PTR (salted_kdf_api);

    VSCF_ASSERT_PTR (salted_kdf_api->set_info_cb);
    salted_kdf_api->set_info_cb (impl, info);
}

//
//  Return salted kdf API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_salted_kdf_api_t *
vscf_salted_kdf_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_SALTED_KDF);
    return (const vscf_salted_kdf_api_t *) api;
}

//
//  Return kdf API.
//
VSCF_PUBLIC const vscf_kdf_api_t *
vscf_salted_kdf_kdf_api(const vscf_salted_kdf_api_t *salted_kdf_api) {

    VSCF_ASSERT_PTR (salted_kdf_api);

    return salted_kdf_api->kdf_api;
}

//
//  Check if given object implements interface 'salted kdf'.
//
VSCF_PUBLIC bool
vscf_salted_kdf_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_SALTED_KDF) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_salted_kdf_api_tag(const vscf_salted_kdf_api_t *salted_kdf_api) {

    VSCF_ASSERT_PTR (salted_kdf_api);

    return salted_kdf_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
