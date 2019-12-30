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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------

#ifndef VSCF_RAW_PRIVATE_KEY_INTERNAL_H_INCLUDED
#define VSCF_RAW_PRIVATE_KEY_INTERNAL_H_INCLUDED

#include "vscf_library.h"
#include "vscf_raw_private_key.h"
#include "vscf_impl.h"

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
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_raw_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_raw_private_key_init_ctx(vscf_raw_private_key_t *self);

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_raw_private_key_cleanup_ctx(vscf_raw_private_key_t *self);

//
//  Creates raw key defined with data and algorithm.
//  Note, data is copied.
//
VSCF_PUBLIC void
vscf_raw_private_key_init_ctx_with_data(vscf_raw_private_key_t *self, vsc_data_t key_data, vscf_impl_t **alg_info_ref);

//
//  Creates raw key defined with buffer and algorithm.
//  Note, data is not copied.
//
VSCF_PUBLIC void
vscf_raw_private_key_init_ctx_with_buffer(vscf_raw_private_key_t *self, vsc_buffer_t **key_data_ref,
        vscf_impl_t **alg_info_ref);

//
//  Creates raw key defined another raw key and new impl tag.
//  Note, data is not copied, but new instance of key is created.s
//
VSCF_PUBLIC void
vscf_raw_private_key_init_ctx_with_redefined_impl_tag(vscf_raw_private_key_t *self, const vscf_raw_private_key_t *other,
        vscf_impl_tag_t impl_tag);

//
//  Creates a fully defined raw key.
//
VSCF_PUBLIC void
vscf_raw_private_key_init_ctx_with_members(vscf_raw_private_key_t *self, vsc_data_t key_data,
        const vscf_impl_t *alg_info, vscf_impl_tag_t impl_tag);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RAW_PRIVATE_KEY_INTERNAL_H_INCLUDED
//  @end
