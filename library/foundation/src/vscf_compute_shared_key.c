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
//  Provide interface to compute shared key for 2 asymmetric keys.
//  Assume that this interface is implemented on the private key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_compute_shared_key.h"
#include "vscf_assert.h"
#include "vscf_compute_shared_key_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Compute shared key for 2 asymmetric keys.
//  Note, shared key can be used only for symmetric cryptography.
//
VSCF_PUBLIC vscf_error_t
vscf_compute_shared_key(vscf_impl_t *impl, const vscf_impl_t *public_key, vsc_buffer_t *shared_key) {

    const vscf_compute_shared_key_api_t *compute_shared_key_api = vscf_compute_shared_key_api (impl);
    VSCF_ASSERT_PTR (compute_shared_key_api);

    VSCF_ASSERT_PTR (compute_shared_key_api->compute_shared_key_cb);
    return compute_shared_key_api->compute_shared_key_cb (impl, public_key, shared_key);
}

//
//  Return number of bytes required to hold shared key.
//
VSCF_PUBLIC size_t
vscf_compute_shared_key_shared_key_len(vscf_impl_t *impl) {

    const vscf_compute_shared_key_api_t *compute_shared_key_api = vscf_compute_shared_key_api (impl);
    VSCF_ASSERT_PTR (compute_shared_key_api);

    VSCF_ASSERT_PTR (compute_shared_key_api->shared_key_len_cb);
    return compute_shared_key_api->shared_key_len_cb (impl);
}

//
//  Return compute shared key API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_compute_shared_key_api_t *
vscf_compute_shared_key_api(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_COMPUTE_SHARED_KEY);
    return (const vscf_compute_shared_key_api_t *) api;
}

//
//  Check if given object implements interface 'compute shared key'.
//
VSCF_PUBLIC bool
vscf_compute_shared_key_is_implemented(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_COMPUTE_SHARED_KEY) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
