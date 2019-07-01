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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provide an interface for signing and verifying data digest
//  with asymmetric keys.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_SIGNER_H_INCLUDED
#define VSCF_KEY_SIGNER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_key_alg.h"
#include "vscf_alg_id.h"
#include "vscf_status.h"
#include "vscf_api.h"

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
//  Contains API requirements of the interface 'key signer'.
//
typedef struct vscf_key_signer_api_t vscf_key_signer_api_t;

//
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_key_signer_can_sign(const vscf_impl_t *impl, const vscf_impl_t *private_key);

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_key_signer_signature_len(const vscf_impl_t *impl, const vscf_impl_t *key);

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_key_signer_sign_hash(const vscf_impl_t *impl, const vscf_impl_t *private_key, vscf_alg_id_t hash_id,
        vsc_data_t digest, vsc_buffer_t *signature) VSCF_NODISCARD;

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_key_signer_can_verify(const vscf_impl_t *impl, const vscf_impl_t *public_key);

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_key_signer_verify_hash(const vscf_impl_t *impl, const vscf_impl_t *public_key, vscf_alg_id_t hash_id,
        vsc_data_t digest, vsc_data_t signature);

//
//  Return key signer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_signer_api_t *
vscf_key_signer_api(const vscf_impl_t *impl);

//
//  Return key alg API.
//
VSCF_PUBLIC const vscf_key_alg_api_t *
vscf_key_signer_key_alg_api(const vscf_key_signer_api_t *key_signer_api);

//
//  Check if given object implements interface 'key signer'.
//
VSCF_PUBLIC bool
vscf_key_signer_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_key_signer_api_tag(const vscf_key_signer_api_t *key_signer_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_SIGNER_H_INCLUDED
//  @end
