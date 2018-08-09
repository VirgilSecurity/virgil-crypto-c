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
//  Provide interface to for key marshaling.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_reader.h"
#include "vscf_assert.h"
#include "vscf_key_reader_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Read public key object.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_reader_read_public_key(vscf_impl_t *impl, vsc_data_t data) {

    const vscf_key_reader_api_t *key_reader_api = vscf_key_reader_api (impl);
    VSCF_ASSERT_PTR (key_reader_api);

    VSCF_ASSERT_PTR (key_reader_api->read_public_key_cb);
    return key_reader_api->read_public_key_cb (impl, data);
}

//
//  Read private key object.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_reader_read_private_key(vscf_impl_t *impl, vsc_data_t data) {

    const vscf_key_reader_api_t *key_reader_api = vscf_key_reader_api (impl);
    VSCF_ASSERT_PTR (key_reader_api);

    VSCF_ASSERT_PTR (key_reader_api->read_private_key_cb);
    return key_reader_api->read_private_key_cb (impl, data);
}

//
//  Return key reader API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_reader_api_t *
vscf_key_reader_api(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_KEY_READER);
    return (const vscf_key_reader_api_t *) api;
}

//
//  Check if given object implements interface 'key reader'.
//
VSCF_PUBLIC bool
vscf_key_reader_is_implemented(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_KEY_READER) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_key_reader_api_tag(const vscf_key_reader_api_t *key_reader_api) {

    VSCF_ASSERT_PTR (key_reader_api);

    return key_reader_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_key_reader_impl_tag(const vscf_key_reader_api_t *key_reader_api) {

    VSCF_ASSERT_PTR (key_reader_api);

    return key_reader_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
