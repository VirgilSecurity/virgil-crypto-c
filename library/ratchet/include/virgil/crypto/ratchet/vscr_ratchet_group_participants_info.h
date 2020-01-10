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
//  Container for array of participants' info
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_H_INCLUDED
#define VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_H_INCLUDED

#include "vscr_library.h"
#include "vscr_status.h"

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'ratchet group participants info' context.
//
typedef struct vscr_ratchet_group_participants_info_t vscr_ratchet_group_participants_info_t;

//
//  Return size of 'vscr_ratchet_group_participants_info_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_participants_info_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_init(vscr_ratchet_group_participants_info_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_cleanup(vscr_ratchet_group_participants_info_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_participants_info_t *
vscr_ratchet_group_participants_info_new(void);

//
//  Perform initialization of pre-allocated context.
//  Creates new array for size elements
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_init_size(vscr_ratchet_group_participants_info_t *self, uint32_t size);

//
//  Allocate class context and perform it's initialization.
//  Creates new array for size elements
//
VSCR_PUBLIC vscr_ratchet_group_participants_info_t *
vscr_ratchet_group_participants_info_new_size(uint32_t size);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_delete(vscr_ratchet_group_participants_info_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_participants_info_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_destroy(vscr_ratchet_group_participants_info_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_participants_info_t *
vscr_ratchet_group_participants_info_shallow_copy(vscr_ratchet_group_participants_info_t *self);

//
//  Add participant info
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_participants_info_add_participant(vscr_ratchet_group_participants_info_t *self, vsc_data_t id,
        vsc_data_t pub_key) VSCR_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_H_INCLUDED
//  @end
