//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Provides generic interface to the Key Encapsulation Mechanism (KEM).
// --------------------------------------------------------------------------

#ifndef VSCF_KEM_H_INCLUDED
#define VSCF_KEM_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"
#include "vscf_api.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
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
//  Contains API requirements of the interface 'kem'.
//
typedef struct vscf_kem_api_t vscf_kem_api_t;

//
//  Return length in bytes required to hold encapsulated shared key.
//
VSCF_PUBLIC size_t
vscf_kem_kem_shared_key_len(const vscf_impl_t *impl, const vscf_impl_t *key);

//
//  Return length in bytes required to hold encapsulated key.
//
VSCF_PUBLIC size_t
vscf_kem_kem_encapsulated_key_len(const vscf_impl_t *impl, const vscf_impl_t *public_key);

//
//  Generate a shared key and a key encapsulated message.
//
VSCF_PUBLIC vscf_status_t
vscf_kem_kem_encapsulate(const vscf_impl_t *impl, const vscf_impl_t *public_key, vsc_buffer_t *shared_key,
        vsc_buffer_t *encapsulated_key) VSCF_NODISCARD;

//
//  Decapsulate the shared key.
//
VSCF_PUBLIC vscf_status_t
vscf_kem_kem_decapsulate(const vscf_impl_t *impl, vsc_data_t encapsulated_key, const vscf_impl_t *private_key,
        vsc_buffer_t *shared_key) VSCF_NODISCARD;

//
//  Return kem API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_kem_api_t *
vscf_kem_api(const vscf_impl_t *impl);

//
//  Check if given object implements interface 'kem'.
//
VSCF_PUBLIC bool
vscf_kem_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_kem_api_tag(const vscf_kem_api_t *kem_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEM_H_INCLUDED
//  @end
