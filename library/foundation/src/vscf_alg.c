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
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Provide interface to persist algorithm information and it parameters
//  and then restore the algorithm from it.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg.h"
#include "vscf_assert.h"
#include "vscf_alg_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_alg_alg_id(const vscf_impl_t *impl) {

    const vscf_alg_api_t *alg_api = vscf_alg_api(impl);
    VSCF_ASSERT_PTR (alg_api);

    VSCF_ASSERT_PTR (alg_api->alg_id_cb);
    return alg_api->alg_id_cb (impl);
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_produce_alg_info(const vscf_impl_t *impl) {

    const vscf_alg_api_t *alg_api = vscf_alg_api(impl);
    VSCF_ASSERT_PTR (alg_api);

    VSCF_ASSERT_PTR (alg_api->produce_alg_info_cb);
    return alg_api->produce_alg_info_cb (impl);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_alg_restore_alg_info(vscf_impl_t *impl, const vscf_impl_t *alg_info) {

    const vscf_alg_api_t *alg_api = vscf_alg_api(impl);
    VSCF_ASSERT_PTR (alg_api);

    VSCF_ASSERT_PTR (alg_api->restore_alg_info_cb);
    return alg_api->restore_alg_info_cb (impl, alg_info);
}

//
//  Return alg API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_alg_api_t *
vscf_alg_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_ALG);
    return (const vscf_alg_api_t *) api;
}

//
//  Check if given object implements interface 'alg'.
//
VSCF_PUBLIC bool
vscf_alg_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_ALG) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_alg_api_tag(const vscf_alg_api_t *alg_api) {

    VSCF_ASSERT_PTR (alg_api);

    return alg_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
