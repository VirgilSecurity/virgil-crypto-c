//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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

#ifndef VSCF_KEY_WRAP_H_INCLUDED
#define VSCF_KEY_WRAP_H_INCLUDED

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

//  @generated_header_includes
// --------------------------------------------------------------------------
// clang-format off
//  Generated header includes start.
// --------------------------------------------------------------------------

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_alg.h"
#include "vscf_status.h"
#include "vscf_api.h"

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
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
//  Contains API requirements of the interface 'key wrap'.
//
typedef struct vscf_key_wrap_api_t vscf_key_wrap_api_t;

//
//  Return buffer length required to hold a wrapped key for the given plain key length.
//
VSCF_PUBLIC size_t
vscf_key_wrap_wrapped_len(const vscf_impl_t *impl, size_t data_len);

//
//  Return buffer length required to hold an unwrapped key for the given wrapped key length.
//
VSCF_PUBLIC size_t
vscf_key_wrap_unwrapped_len(const vscf_impl_t *impl, size_t data_len);

//
//  Wrap given key data using the Key Encryption Key (KEK).
//
VSCF_PUBLIC vscf_status_t
vscf_key_wrap_wrap(vscf_impl_t *impl, vsc_data_t kek, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Unwrap given key data using the Key Encryption Key (KEK).
//
VSCF_PUBLIC vscf_status_t
vscf_key_wrap_unwrap(vscf_impl_t *impl, vsc_data_t kek, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return key wrap API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_wrap_api_t *
vscf_key_wrap_api(const vscf_impl_t *impl);

//
//  Return alg API.
//
VSCF_PUBLIC const vscf_alg_api_t *
vscf_key_wrap_alg_api(const vscf_key_wrap_api_t *key_wrap_api);

//
//  Check if given object implements interface 'key wrap'.
//
VSCF_PUBLIC bool
vscf_key_wrap_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_key_wrap_api_tag(const vscf_key_wrap_api_t *key_wrap_api);

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end

#ifdef __cplusplus
}
#endif

//  @footer
#endif // VSCF_KEY_WRAP_H_INCLUDED
//  @end
