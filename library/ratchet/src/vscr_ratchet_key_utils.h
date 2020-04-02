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
//  Utils class for working with keys formats.
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_KEY_UTILS_H_INCLUDED
#define VSCR_RATCHET_KEY_UTILS_H_INCLUDED

#include "vscr_library.h"
#include "vscr_ratchet_common.h"
#include "vscr_error.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_status.h"

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'ratchet key utils' context.
//
typedef struct vscr_ratchet_key_utils_t vscr_ratchet_key_utils_t;

//
//  Return size of 'vscr_ratchet_key_utils_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_key_utils_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_init(vscr_ratchet_key_utils_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_cleanup(vscr_ratchet_key_utils_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_key_utils_t *
vscr_ratchet_key_utils_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_delete(vscr_ratchet_key_utils_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_key_utils_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_destroy(vscr_ratchet_key_utils_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_key_utils_t *
vscr_ratchet_key_utils_shallow_copy(vscr_ratchet_key_utils_t *self);

VSCR_PUBLIC vscr_status_t
vscr_ratchet_key_utils_import_private_key(vscr_ratchet_key_utils_t *self, const vscf_impl_t *private_key,
        vscr_ratchet_private_key_t *private_key_first, const vscf_impl_t **private_key_second_ref,
        const vscf_impl_t **private_key_second_signer_ref, bool enable_post_quantum, bool with_signer) VSCR_NODISCARD;

VSCR_PUBLIC vscr_status_t
vscr_ratchet_key_utils_import_public_key(vscr_ratchet_key_utils_t *self, const vscf_impl_t *public_key,
        vscr_ratchet_public_key_t *public_key_first, const vscf_impl_t **public_key_second_ref,
        const vscf_impl_t **public_key_second_signer_ref, bool enable_post_quantum, bool with_signer) VSCR_NODISCARD;

VSCR_PUBLIC void
vscr_ratchet_key_utils_compute_public_key_id(vscr_ratchet_key_utils_t *self,
        const vscr_ratchet_public_key_t public_key_first, vsc_data_t public_key_second, vscr_ratchet_key_id_t key_id);

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_key_utils_extract_ratchet_public_key(vscr_ratchet_key_utils_t *self, vsc_data_t data, bool ed25519,
        bool curve25519, bool convert_to_curve25519, vscr_error_t *error);

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_key_utils_extract_ratchet_private_key(vscr_ratchet_key_utils_t *self, vsc_data_t data, bool ed25519,
        bool curve25519, bool convert_to_curve25519, vscr_error_t *error);

VSCR_PUBLIC vscr_ratchet_chain_key_t *
vscr_ratchet_key_utils_derive_participant_key(const vscr_ratchet_symmetric_key_t root_key,
        const vscr_ratchet_participant_id_t participant_id);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_KEY_UTILS_H_INCLUDED
//  @end
