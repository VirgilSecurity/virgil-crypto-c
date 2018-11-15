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
//  Public and private key serialization to an interchangeable format.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_serializer.h"
#include "vscf_assert.h"
#include "vscf_key_serializer_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_serializer_serialized_public_key_len(vscf_impl_t *impl, const vscf_impl_t *public_key) {

    const vscf_key_serializer_api_t *key_serializer_api = vscf_key_serializer_api (impl);
    VSCF_ASSERT_PTR (key_serializer_api);

    VSCF_ASSERT_PTR (key_serializer_api->serialized_public_key_len_cb);
    return key_serializer_api->serialized_public_key_len_cb (impl, public_key);
}

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_error_t
vscf_key_serializer_serialize_public_key(vscf_impl_t *impl, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    const vscf_key_serializer_api_t *key_serializer_api = vscf_key_serializer_api (impl);
    VSCF_ASSERT_PTR (key_serializer_api);

    VSCF_ASSERT_PTR (key_serializer_api->serialize_public_key_cb);
    return key_serializer_api->serialize_public_key_cb (impl, public_key, out);
}

//
//  Calculate buffer size enough to hold serialized private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_serializer_serialized_private_key_len(vscf_impl_t *impl, const vscf_impl_t *private_key) {

    const vscf_key_serializer_api_t *key_serializer_api = vscf_key_serializer_api (impl);
    VSCF_ASSERT_PTR (key_serializer_api);

    VSCF_ASSERT_PTR (key_serializer_api->serialized_private_key_len_cb);
    return key_serializer_api->serialized_private_key_len_cb (impl, private_key);
}

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_error_t
vscf_key_serializer_serialize_private_key(vscf_impl_t *impl, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    const vscf_key_serializer_api_t *key_serializer_api = vscf_key_serializer_api (impl);
    VSCF_ASSERT_PTR (key_serializer_api);

    VSCF_ASSERT_PTR (key_serializer_api->serialize_private_key_cb);
    return key_serializer_api->serialize_private_key_cb (impl, private_key, out);
}

//
//  Return key serializer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_serializer_api_t *
vscf_key_serializer_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_KEY_SERIALIZER);
    return (const vscf_key_serializer_api_t *) api;
}

//
//  Check if given object implements interface 'key serializer'.
//
VSCF_PUBLIC bool
vscf_key_serializer_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_KEY_SERIALIZER) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_key_serializer_api_tag(const vscf_key_serializer_api_t *key_serializer_api) {

    VSCF_ASSERT_PTR (key_serializer_api);

    return key_serializer_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_key_serializer_impl_tag(const vscf_key_serializer_api_t *key_serializer_api) {

    VSCF_ASSERT_PTR (key_serializer_api);

    return key_serializer_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
