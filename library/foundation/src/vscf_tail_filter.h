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
//  This class filter incoming data stream to keep a tail of the given length.
// --------------------------------------------------------------------------

#ifndef VSCF_TAIL_FILTER_H_INCLUDED
#define VSCF_TAIL_FILTER_H_INCLUDED

#include "vscf_library.h"

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
//  Handle 'tail filter' context.
//
typedef struct vscf_tail_filter_t vscf_tail_filter_t;

//
//  Return size of 'vscf_tail_filter_t'.
//
VSCF_PUBLIC size_t
vscf_tail_filter_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_tail_filter_init(vscf_tail_filter_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_tail_filter_cleanup(vscf_tail_filter_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_tail_filter_t *
vscf_tail_filter_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_tail_filter_delete(vscf_tail_filter_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_tail_filter_new ()'.
//
VSCF_PUBLIC void
vscf_tail_filter_destroy(vscf_tail_filter_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_tail_filter_t *
vscf_tail_filter_shallow_copy(vscf_tail_filter_t *self);

//
//  Prepare filter for a new byte stream.
//
VSCF_PUBLIC void
vscf_tail_filter_reset(vscf_tail_filter_t *self, size_t len);

//
//  Return filtered tail.
//
VSCF_PUBLIC vsc_data_t
vscf_tail_filter_tail(vscf_tail_filter_t *self);

//
//  Process given data and return filtered data guaranteed without a tail.
//
VSCF_PUBLIC void
vscf_tail_filter_process(vscf_tail_filter_t *self, vsc_data_t data, vsc_buffer_t *out);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_TAIL_FILTER_H_INCLUDED
//  @end
