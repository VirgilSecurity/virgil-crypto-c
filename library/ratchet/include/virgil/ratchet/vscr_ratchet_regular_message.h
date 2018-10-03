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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_REGULAR_MESSAGE_H_INCLUDED
#define VSCR_RATCHET_REGULAR_MESSAGE_H_INCLUDED

#include "vscr_library.h"
#include "vscr_error.h"
#include "vscr_error_ctx.h"

#include <virgil/foundation/vscf_error_ctx.h>
#include <virgil/common/vsc_buffer.h>
#include <virgil/common/vsc_data.h>
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
//  Public integral constants.
//
enum {
    vscr_ratchet_regular_message_PUBLIC_KEY_LENGTH = 32,
    //
    //  FIXME
    //
    vscr_ratchet_regular_message_MAX_MESSAGE_LENGTH = 1024 * 1024 * 1024
};

//
//  Handle 'ratchet regular message' context.
//
typedef struct vscr_ratchet_regular_message_t vscr_ratchet_regular_message_t;
struct vscr_ratchet_regular_message_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    uint8_t version;

    uint32_t counter;

    vsc_buffer_t *public_key;

    vsc_buffer_t *cipher_text;
};

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_init(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_cleanup(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_new(void);

VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_new_with_members(uint8_t version, uint32_t counter, vsc_buffer_t *public_key,
        vsc_buffer_t *cipher_text);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_delete(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_regular_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_destroy(vscr_ratchet_regular_message_t **ratchet_regular_message_ctx_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_copy(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx);

VSCR_PUBLIC size_t
vscr_ratchet_regular_message_serialize_len(size_t cipher_text_len);

VSCR_PUBLIC vscr_error_t
vscr_ratchet_regular_message_serialize(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx,
        vsc_buffer_t *output);

VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_REGULAR_MESSAGE_H_INCLUDED
//  @end
