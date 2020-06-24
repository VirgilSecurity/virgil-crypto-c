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

#ifndef VSSC_JWT_PRIVATE_H_INCLUDED
#define VSSC_JWT_PRIVATE_H_INCLUDED

#include "vssc_jwt.h"
#include "vssc_jwt_header.h"
#include "vssc_jwt_payload.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str_buffer.h>
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_str.h>
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
//  Perform initialization of pre-allocated context.
//  Create object with all members defined.
//
VSSC_PUBLIC void
vssc_jwt_init_with_members_disown(vssc_jwt_t *self, vssc_jwt_header_t **header_ref, vssc_jwt_payload_t **payload_ref,
        vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref);

//
//  Allocate class context and perform it's initialization.
//  Create object with all members defined.
//
VSSC_PUBLIC vssc_jwt_t *
vssc_jwt_new_with_members_disown(vssc_jwt_header_t **header_ref, vssc_jwt_payload_t **payload_ref,
        vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref);

//
//  Return JWT Header string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_get_header_string(const vssc_jwt_t *self);

//
//  Return JWT Payload string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_get_payload_string(const vssc_jwt_t *self);

//
//  Return JWT Signature string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_get_signature_string(const vssc_jwt_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_JWT_PRIVATE_H_INCLUDED
//  @end
