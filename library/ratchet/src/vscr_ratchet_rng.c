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
//  Interface for ratchet rng
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_rng.h"
#include "vscr_assert.h"
#include "vscr_ratchet_rng_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Interface for ratchet rng
//
VSCR_PUBLIC void
vscr_ratchet_rng_generate_random_data(vscr_impl_t *impl, size_t size, vsc_buffer_t *random) {

    const vscr_ratchet_rng_api_t *ratchet_rng_api = vscr_ratchet_rng_api (impl);
    VSCR_ASSERT_PTR (ratchet_rng_api);

    VSCR_ASSERT_PTR (ratchet_rng_api->generate_random_data_cb);
    ratchet_rng_api->generate_random_data_cb (impl, size, random);
}

//
//  Return ratchet rng API, or NULL if it is not implemented.
//
VSCR_PUBLIC const vscr_ratchet_rng_api_t *
vscr_ratchet_rng_api(vscr_impl_t *impl) {

    VSCR_ASSERT_PTR (impl);

    const vscr_api_t *api = vscr_impl_api (impl, vscr_api_tag_RATCHET_RNG);
    return (const vscr_ratchet_rng_api_t *) api;
}

//
//  Check if given object implements interface 'ratchet rng'.
//
VSCR_PUBLIC bool
vscr_ratchet_rng_is_implemented(vscr_impl_t *impl) {

    VSCR_ASSERT_PTR (impl);

    return vscr_impl_api (impl, vscr_api_tag_RATCHET_RNG) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCR_PUBLIC vscr_api_tag_t
vscr_ratchet_rng_api_tag(const vscr_ratchet_rng_api_t *ratchet_rng_api) {

    VSCR_ASSERT_PTR (ratchet_rng_api);

    return ratchet_rng_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCR_PUBLIC vscr_impl_tag_t
vscr_ratchet_rng_impl_tag(const vscr_ratchet_rng_api_t *ratchet_rng_api) {

    VSCR_ASSERT_PTR (ratchet_rng_api);

    return ratchet_rng_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
