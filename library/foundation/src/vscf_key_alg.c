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
//  Common information about asymmetric key algorithm.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_alg.h"
#include "vscf_assert.h"
#include "vscf_key_alg_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Extract public key from the private key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_extract_public_key(const vscf_impl_t *impl, const vscf_impl_t *private_key, vscf_error_t *error) {

    const vscf_key_alg_api_t *key_alg_api = vscf_key_alg_api(impl);
    VSCF_ASSERT_PTR (key_alg_api);

    VSCF_ASSERT_PTR (key_alg_api->extract_public_key_cb);
    return key_alg_api->extract_public_key_cb (impl, private_key, error);
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_generate_ephemeral_key(const vscf_impl_t *impl, const vscf_impl_t *key, vscf_error_t *error) {

    const vscf_key_alg_api_t *key_alg_api = vscf_key_alg_api(impl);
    VSCF_ASSERT_PTR (key_alg_api);

    VSCF_ASSERT_PTR (key_alg_api->generate_ephemeral_key_cb);
    return key_alg_api->generate_ephemeral_key_cb (impl, key, error);
}

//
//  Import public key from the raw binary format.
//
//  Return public key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_import_public_key(vscf_impl_t *impl, const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    const vscf_key_alg_api_t *key_alg_api = vscf_key_alg_api(impl);
    VSCF_ASSERT_PTR (key_alg_api);

    VSCF_ASSERT_PTR (key_alg_api->import_public_key_cb);
    return key_alg_api->import_public_key_cb (impl, raw_key, error);
}

//
//  Export public key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_key_alg_export_public_key(const vscf_impl_t *impl, const vscf_impl_t *public_key, vscf_error_t *error) {

    const vscf_key_alg_api_t *key_alg_api = vscf_key_alg_api(impl);
    VSCF_ASSERT_PTR (key_alg_api);

    VSCF_ASSERT_PTR (key_alg_api->export_public_key_cb);
    return key_alg_api->export_public_key_cb (impl, public_key, error);
}

//
//  Import private key from the raw binary format.
//
//  Return private key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_alg_import_private_key(vscf_impl_t *impl, const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    const vscf_key_alg_api_t *key_alg_api = vscf_key_alg_api(impl);
    VSCF_ASSERT_PTR (key_alg_api);

    VSCF_ASSERT_PTR (key_alg_api->import_private_key_cb);
    return key_alg_api->import_private_key_cb (impl, raw_key, error);
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_key_alg_export_private_key(const vscf_impl_t *impl, const vscf_impl_t *private_key, vscf_error_t *error) {

    const vscf_key_alg_api_t *key_alg_api = vscf_key_alg_api(impl);
    VSCF_ASSERT_PTR (key_alg_api);

    VSCF_ASSERT_PTR (key_alg_api->export_private_key_cb);
    return key_alg_api->export_private_key_cb (impl, private_key, error);
}

//
//  Returns constant 'can import public key'.
//
VSCF_PUBLIC bool
vscf_key_alg_can_import_public_key(const vscf_key_alg_api_t *key_alg_api) {

    VSCF_ASSERT_PTR (key_alg_api);

    return key_alg_api->can_import_public_key;
}

//
//  Returns constant 'can export public key'.
//
VSCF_PUBLIC bool
vscf_key_alg_can_export_public_key(const vscf_key_alg_api_t *key_alg_api) {

    VSCF_ASSERT_PTR (key_alg_api);

    return key_alg_api->can_export_public_key;
}

//
//  Returns constant 'can import private key'.
//
VSCF_PUBLIC bool
vscf_key_alg_can_import_private_key(const vscf_key_alg_api_t *key_alg_api) {

    VSCF_ASSERT_PTR (key_alg_api);

    return key_alg_api->can_import_private_key;
}

//
//  Returns constant 'can export private key'.
//
VSCF_PUBLIC bool
vscf_key_alg_can_export_private_key(const vscf_key_alg_api_t *key_alg_api) {

    VSCF_ASSERT_PTR (key_alg_api);

    return key_alg_api->can_export_private_key;
}

//
//  Return key alg API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_alg_api_t *
vscf_key_alg_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_KEY_ALG);
    return (const vscf_key_alg_api_t *) api;
}

//
//  Return alg API.
//
VSCF_PUBLIC const vscf_alg_api_t *
vscf_key_alg_alg_api(const vscf_key_alg_api_t *key_alg_api) {

    VSCF_ASSERT_PTR (key_alg_api);

    return key_alg_api->alg_api;
}

//
//  Check if given object implements interface 'key alg'.
//
VSCF_PUBLIC bool
vscf_key_alg_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_KEY_ALG) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_key_alg_api_tag(const vscf_key_alg_api_t *key_alg_api) {

    VSCF_ASSERT_PTR (key_alg_api);

    return key_alg_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
