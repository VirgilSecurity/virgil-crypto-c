//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
//  Class responsible for operations with Virgil Cards and it's representations.
// --------------------------------------------------------------------------

#ifndef VSSC_CARD_MANAGER_H_INCLUDED
#define VSSC_CARD_MANAGER_H_INCLUDED

#include "vssc_library.h"
#include "vssc_status.h"
#include "vssc_error.h"
#include "vssc_raw_card.h"
#include "vssc_card.h"
#include "vssc_raw_card_list.h"
#include "vssc_card_list.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
//  Handle 'card manager' context.
//
#ifndef VSSC_CARD_MANAGER_T_DEFINED
#define VSSC_CARD_MANAGER_T_DEFINED
    typedef struct vssc_card_manager_t vssc_card_manager_t;
#endif // VSSC_CARD_MANAGER_T_DEFINED

//
//  Return size of 'vssc_card_manager_t'.
//
VSSC_PUBLIC size_t
vssc_card_manager_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_manager_init(vssc_card_manager_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_manager_cleanup(vssc_card_manager_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_manager_t *
vssc_card_manager_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_manager_delete(const vssc_card_manager_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_manager_new ()'.
//
VSSC_PUBLIC void
vssc_card_manager_destroy(vssc_card_manager_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_manager_t *
vssc_card_manager_shallow_copy(vssc_card_manager_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_card_manager_t *
vssc_card_manager_shallow_copy_const(const vssc_card_manager_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSC_PUBLIC void
vssc_card_manager_use_random(vssc_card_manager_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSC_PUBLIC void
vssc_card_manager_take_random(vssc_card_manager_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSC_PUBLIC void
vssc_card_manager_release_random(vssc_card_manager_t *self);

//
//  Configure internal states and dependencies.
//
VSSC_PUBLIC vssc_status_t
vssc_card_manager_configure(vssc_card_manager_t *self) VSSC_NODISCARD;

//
//  Configure internal states and dependencies.
//  Virgil Service Public Key can be customized (i.e. for stage env).
//
VSSC_PUBLIC vssc_status_t
vssc_card_manager_configure_with_service_public_key(vssc_card_manager_t *self,
        vsc_data_t public_key_data) VSSC_NODISCARD;

//
//  Generates self-signed "raw card".
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_manager_generate_raw_card(const vssc_card_manager_t *self, vsc_str_t identity, const vscf_impl_t *private_key,
        vssc_error_t *error);

//
//  Generates self-signed "raw card" with a defined previous card id.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_manager_generate_replacement_raw_card(const vssc_card_manager_t *self, vsc_str_t identity,
        const vscf_impl_t *private_key, vsc_str_t previous_card_id, vssc_error_t *error);

//
//  Create Card from "raw card" and verify it.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_manager_import_raw_card(const vssc_card_manager_t *self, const vssc_raw_card_t *raw_card,
        vssc_error_t *error);

//
//  Create list of Cards from "raw card list" and verify it.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_list_t *
vssc_card_manager_import_raw_card_list(const vssc_card_manager_t *self, const vssc_raw_card_list_t *raw_card_list,
        vssc_error_t *error);

//
//  Create Card with expected card identifier from "raw card" and verify it.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_manager_import_raw_card_with_id(const vssc_card_manager_t *self, const vssc_raw_card_t *raw_card,
        vsc_str_t card_id, vssc_error_t *error);

//
//  Create Card from "raw card" with additional check which ensures
//  that Virgil Cards Service do not change self-signature.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_manager_import_raw_card_with_initial_raw_card(const vssc_card_manager_t *self,
        const vssc_raw_card_t *raw_card, const vssc_raw_card_t *initial_raw_card, vssc_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_CARD_MANAGER_H_INCLUDED
//  @end
