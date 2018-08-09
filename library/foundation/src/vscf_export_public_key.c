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
//  Provide interface for exporting public key to the binary format.
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_export_public_key.h"
#include "vscf_assert.h"
#include "vscf_export_public_key_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Export public key in the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_export_public_key(vscf_impl_t *impl, vsc_buffer_t *out) {

    const vscf_export_public_key_api_t *export_public_key_api = vscf_export_public_key_api (impl);
    VSCF_ASSERT_PTR (export_public_key_api);

    VSCF_ASSERT_PTR (export_public_key_api->export_public_key_cb);
    return export_public_key_api->export_public_key_cb (impl, out);
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_export_public_key_exported_public_key_len(vscf_impl_t *impl) {

    const vscf_export_public_key_api_t *export_public_key_api = vscf_export_public_key_api (impl);
    VSCF_ASSERT_PTR (export_public_key_api);

    VSCF_ASSERT_PTR (export_public_key_api->exported_public_key_len_cb);
    return export_public_key_api->exported_public_key_len_cb (impl);
}

//
//  Return export public key API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_export_public_key_api_t *
vscf_export_public_key_api(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_EXPORT_PUBLIC_KEY);
    return (const vscf_export_public_key_api_t *) api;
}

//
//  Check if given object implements interface 'export public key'.
//
VSCF_PUBLIC bool
vscf_export_public_key_is_implemented(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_EXPORT_PUBLIC_KEY) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_export_public_key_api_tag(const vscf_export_public_key_api_t *export_public_key_api) {

    VSCF_ASSERT_PTR (export_public_key_api);

    return export_public_key_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_export_public_key_impl_tag(const vscf_export_public_key_api_t *export_public_key_api) {

    VSCF_ASSERT_PTR (export_public_key_api);

    return export_public_key_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
