//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Interface 'key alg' API.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_ALG_API_H_INCLUDED
#define VSCF_KEY_ALG_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_error.h"
#include "vscf_raw_public_key.h"
#include "vscf_status.h"
#include "vscf_raw_private_key.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Callback. Generate ephemeral private key of the same type.
//          Note, this operation might be slow.
//
typedef vscf_impl_t * (*vscf_key_alg_api_generate_ephemeral_key_fn)(const vscf_impl_t *impl, const vscf_impl_t *key,
        vscf_error_t *error);

//
//  Callback. Import public key from the raw binary format.
//
//          Return public key that is adopted and optimized to be used
//          with this particular algorithm.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA public key must be imported from the format defined in
//          RFC 3447 Appendix A.1.1.
//
typedef vscf_impl_t * (*vscf_key_alg_api_import_public_key_fn)(const vscf_impl_t *impl,
        const vscf_raw_public_key_t *raw_key, vscf_error_t *error);

//
//  Callback. Import public key from the raw binary format.
//
typedef vscf_impl_t * (*vscf_key_alg_api_import_public_key_data_fn)(const vscf_impl_t *impl, vsc_data_t key_data,
        const vscf_impl_t *key_alg_info, vscf_error_t *error);

//
//  Callback. Export public key to the raw binary format.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA public key must be exported in format defined in
//          RFC 3447 Appendix A.1.1.
//
typedef vscf_raw_public_key_t * (*vscf_key_alg_api_export_public_key_fn)(const vscf_impl_t *impl,
        const vscf_impl_t *public_key, vscf_error_t *error);

//
//  Callback. Return length in bytes required to hold exported public key.
//
typedef size_t (*vscf_key_alg_api_exported_public_key_data_len_fn)(const vscf_impl_t *impl,
        const vscf_impl_t *public_key);

//
//  Callback. Export public key to the raw binary format without algorithm information.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA public key must be exported in format defined in
//          RFC 3447 Appendix A.1.1.
//
typedef vscf_status_t (*vscf_key_alg_api_export_public_key_data_fn)(const vscf_impl_t *impl,
        const vscf_impl_t *public_key, vsc_buffer_t *out);

//
//  Callback. Import private key from the raw binary format.
//
//          Return private key that is adopted and optimized to be used
//          with this particular algorithm.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA private key must be imported from the format defined in
//          RFC 3447 Appendix A.1.2.
//
typedef vscf_impl_t * (*vscf_key_alg_api_import_private_key_fn)(const vscf_impl_t *impl,
        const vscf_raw_private_key_t *raw_key, vscf_error_t *error);

//
//  Callback. Import private key from the raw binary format.
//
typedef vscf_impl_t * (*vscf_key_alg_api_import_private_key_data_fn)(const vscf_impl_t *impl, vsc_data_t key_data,
        const vscf_impl_t *key_alg_info, vscf_error_t *error);

//
//  Callback. Export private key in the raw binary format.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA private key must be exported in format defined in
//          RFC 3447 Appendix A.1.2.
//
typedef vscf_raw_private_key_t * (*vscf_key_alg_api_export_private_key_fn)(const vscf_impl_t *impl,
        const vscf_impl_t *private_key, vscf_error_t *error);

//
//  Callback. Return length in bytes required to hold exported private key.
//
typedef size_t (*vscf_key_alg_api_exported_private_key_data_len_fn)(const vscf_impl_t *impl,
        const vscf_impl_t *private_key);

//
//  Callback. Export private key to the raw binary format without algorithm information.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA private key must be exported in format defined in
//          RFC 3447 Appendix A.1.2.
//
typedef vscf_status_t (*vscf_key_alg_api_export_private_key_data_fn)(const vscf_impl_t *impl,
        const vscf_impl_t *private_key, vsc_buffer_t *out);

//
//  Contains API requirements of the interface 'key alg'.
//
struct vscf_key_alg_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key_alg' MUST be equal to the 'vscf_api_tag_KEY_ALG'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Generate ephemeral private key of the same type.
    //  Note, this operation might be slow.
    //
    vscf_key_alg_api_generate_ephemeral_key_fn generate_ephemeral_key_cb;
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
    vscf_key_alg_api_import_public_key_fn import_public_key_cb;
    //
    //  Import public key from the raw binary format.
    //
    vscf_key_alg_api_import_public_key_data_fn import_public_key_data_cb;
    //
    //  Export public key to the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    vscf_key_alg_api_export_public_key_fn export_public_key_cb;
    //
    //  Return length in bytes required to hold exported public key.
    //
    vscf_key_alg_api_exported_public_key_data_len_fn exported_public_key_data_len_cb;
    //
    //  Export public key to the raw binary format without algorithm information.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    vscf_key_alg_api_export_public_key_data_fn export_public_key_data_cb;
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
    vscf_key_alg_api_import_private_key_fn import_private_key_cb;
    //
    //  Import private key from the raw binary format.
    //
    vscf_key_alg_api_import_private_key_data_fn import_private_key_data_cb;
    //
    //  Export private key in the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    vscf_key_alg_api_export_private_key_fn export_private_key_cb;
    //
    //  Return length in bytes required to hold exported private key.
    //
    vscf_key_alg_api_exported_private_key_data_len_fn exported_private_key_data_len_cb;
    //
    //  Export private key to the raw binary format without algorithm information.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    vscf_key_alg_api_export_private_key_data_fn export_private_key_data_cb;
    //
    //  Defines whether a public key can be imported or not.
    //
    bool can_import_public_key;
    //
    //  Define whether a public key can be exported or not.
    //
    bool can_export_public_key;
    //
    //  Define whether a private key can be imported or not.
    //
    bool can_import_private_key;
    //
    //  Define whether a private key can be exported or not.
    //
    bool can_export_private_key;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_ALG_API_H_INCLUDED
//  @end
