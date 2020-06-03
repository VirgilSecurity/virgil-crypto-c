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
//  Class responsible for signing "raw card".
// --------------------------------------------------------------------------

#ifndef VSSC_RAW_CARD_SIGNER_H_INCLUDED
#define VSSC_RAW_CARD_SIGNER_H_INCLUDED

#include "vssc_library.h"
#include "vssc_raw_card.h"
#include "vssc_status.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
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
//  Handle 'raw card signer' context.
//
typedef struct vssc_raw_card_signer_t vssc_raw_card_signer_t;

//
//  Return size of 'vssc_raw_card_signer_t'.
//
VSSC_PUBLIC size_t
vssc_raw_card_signer_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_raw_card_signer_init(vssc_raw_card_signer_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_raw_card_signer_cleanup(vssc_raw_card_signer_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_raw_card_signer_t *
vssc_raw_card_signer_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_raw_card_signer_delete(const vssc_raw_card_signer_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_raw_card_signer_new ()'.
//
VSSC_PUBLIC void
vssc_raw_card_signer_destroy(vssc_raw_card_signer_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_raw_card_signer_t *
vssc_raw_card_signer_shallow_copy(vssc_raw_card_signer_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_raw_card_signer_t *
vssc_raw_card_signer_shallow_copy_const(const vssc_raw_card_signer_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSC_PUBLIC void
vssc_raw_card_signer_use_random(vssc_raw_card_signer_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSC_PUBLIC void
vssc_raw_card_signer_take_random(vssc_raw_card_signer_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSC_PUBLIC void
vssc_raw_card_signer_release_random(vssc_raw_card_signer_t *self);

//
//  Adds signature to given "raw card" with provided signer and private key.
//
VSSC_PUBLIC vssc_status_t
vssc_raw_card_signer_sign(const vssc_raw_card_signer_t *self, vssc_raw_card_t *raw_card, vsc_str_t signer_id,
        const vscf_impl_t *private_key) VSSC_NODISCARD;

//
//  Adds self-signature to given "raw card".
//
VSSC_PUBLIC vssc_status_t
vssc_raw_card_signer_self_sign(const vssc_raw_card_signer_t *self, vssc_raw_card_t *raw_card,
        const vscf_impl_t *private_key) VSSC_NODISCARD;

//
//  Adds Virgil Signature to given "raw card".
//
VSSC_PUBLIC vssc_status_t
vssc_raw_card_signer_virgil_sign(const vssc_raw_card_signer_t *self, vssc_raw_card_t *raw_card,
        const vscf_impl_t *private_key) VSSC_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_RAW_CARD_SIGNER_H_INCLUDED
//  @end
