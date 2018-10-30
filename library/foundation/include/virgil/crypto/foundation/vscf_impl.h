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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains common functionality for all 'implementation' object.
//  It is also enumerate all available implementations within crypto libary.
// --------------------------------------------------------------------------

#ifndef VSCF_IMPL_H_INCLUDED
#define VSCF_IMPL_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"

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
//  Enumerates all possible implementations within crypto library.
//
enum vscf_impl_tag_t {
    vscf_impl_tag_BEGIN = 0,
    vscf_impl_tag_AES256_GCM,
    vscf_impl_tag_ASN1RD,
    vscf_impl_tag_ASN1WR,
    vscf_impl_tag_CTR_DRBG,
    vscf_impl_tag_ENTROPY_ACCUMULATOR,
    vscf_impl_tag_FAKE_RANDOM,
    vscf_impl_tag_HKDF,
    vscf_impl_tag_HMAC,
    vscf_impl_tag_KDF1,
    vscf_impl_tag_KDF2,
    vscf_impl_tag_PLATFORM_ENTROPY,
    vscf_impl_tag_RSA_PRIVATE_KEY,
    vscf_impl_tag_RSA_PUBLIC_KEY,
    vscf_impl_tag_SHA224,
    vscf_impl_tag_SHA256,
    vscf_impl_tag_SHA384,
    vscf_impl_tag_SHA512,
    vscf_impl_tag_END
};
typedef enum vscf_impl_tag_t vscf_impl_tag_t;

//
//  Generic type for any 'implementation'.
//
typedef struct vscf_impl_t vscf_impl_t;

//
//  Return 'API' object that is fulfiled with a meta information
//  specific to the given implementation object.
//  Or NULL if object does not implement requested 'API'.
//
VSCF_PUBLIC const vscf_api_t *
vscf_impl_api(vscf_impl_t *impl, vscf_api_tag_t api_tag);

//
//  Return unique 'Implementation TAG'.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_impl_tag(vscf_impl_t *impl);

//
//  Cleanup implementation object and it's dependencies.
//
VSCF_PUBLIC void
vscf_impl_cleanup(vscf_impl_t *impl);

//
//  Delete implementation object and it's dependencies.
//
VSCF_PUBLIC void
vscf_impl_delete(vscf_impl_t *impl);

//
//  Destroy implementation object and it's dependencies.
//
VSCF_PUBLIC void
vscf_impl_destroy(vscf_impl_t **impl_ref);

//
//  Copy implementation object by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_impl_t *
vscf_impl_copy(vscf_impl_t *impl);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_IMPL_H_INCLUDED
//  @end
