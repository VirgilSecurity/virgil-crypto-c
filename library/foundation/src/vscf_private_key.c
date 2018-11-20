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
//  Contains private part of the key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_private_key.h"
#include "vscf_assert.h"
#include "vscf_private_key_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_private_key_extract_public_key(const vscf_impl_t *impl) {

    const vscf_private_key_api_t *private_key_api = vscf_private_key_api (impl);
    VSCF_ASSERT_PTR (private_key_api);

    VSCF_ASSERT_PTR (private_key_api->extract_public_key_cb);
    return private_key_api->extract_public_key_cb (impl);
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_private_key_export_private_key(const vscf_impl_t *impl, vsc_buffer_t *out) {

    const vscf_private_key_api_t *private_key_api = vscf_private_key_api (impl);
    VSCF_ASSERT_PTR (private_key_api);

    VSCF_ASSERT_PTR (private_key_api->export_private_key_cb);
    return private_key_api->export_private_key_cb (impl, out);
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_private_key_exported_private_key_len(const vscf_impl_t *impl) {

    const vscf_private_key_api_t *private_key_api = vscf_private_key_api (impl);
    VSCF_ASSERT_PTR (private_key_api);

    VSCF_ASSERT_PTR (private_key_api->exported_private_key_len_cb);
    return private_key_api->exported_private_key_len_cb (impl);
}

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_private_key_import_private_key(vscf_impl_t *impl, vsc_data_t data) {

    const vscf_private_key_api_t *private_key_api = vscf_private_key_api (impl);
    VSCF_ASSERT_PTR (private_key_api);

    VSCF_ASSERT_PTR (private_key_api->import_private_key_cb);
    return private_key_api->import_private_key_cb (impl, data);
}

//
//  Returns constant 'can export private key'.
//
VSCF_PUBLIC bool
vscf_private_key_can_export_private_key(const vscf_private_key_api_t *private_key_api) {

    VSCF_ASSERT_PTR (private_key_api);

    return private_key_api->can_export_private_key;
}

//
//  Returns constant 'can import private key'.
//
VSCF_PUBLIC bool
vscf_private_key_can_import_private_key(const vscf_private_key_api_t *private_key_api) {

    VSCF_ASSERT_PTR (private_key_api);

    return private_key_api->can_import_private_key;
}

//
//  Return private key API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_private_key_api_t *
vscf_private_key_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_PRIVATE_KEY);
    return (const vscf_private_key_api_t *) api;
}

//
//  Return key API.
//
VSCF_PUBLIC const vscf_key_api_t *
vscf_private_key_key_api(const vscf_private_key_api_t *private_key_api) {

    VSCF_ASSERT_PTR (private_key_api);

    return private_key_api->key_api;
}

//
//  Check if given object implements interface 'private key'.
//
VSCF_PUBLIC bool
vscf_private_key_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_PRIVATE_KEY) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_private_key_api_tag(const vscf_private_key_api_t *private_key_api) {

    VSCF_ASSERT_PTR (private_key_api);

    return private_key_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
