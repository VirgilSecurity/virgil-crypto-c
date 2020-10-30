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
//  Contains messenger configuration.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CONFIG_H_INCLUDED
#define VSSQ_MESSENGER_CONFIG_H_INCLUDED

#include "vssq_library.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'messenger config' context.
//
#ifndef VSSQ_MESSENGER_CONFIG_T_DEFINED
#define VSSQ_MESSENGER_CONFIG_T_DEFINED
    typedef struct vssq_messenger_config_t vssq_messenger_config_t;
#endif // VSSQ_MESSENGER_CONFIG_T_DEFINED

VSSQ_PUBLIC extern const char vssq_messenger_config_k_base_url_virgil_chars[];

VSSQ_PUBLIC extern const vsc_str_t vssq_messenger_config_k_base_url_virgil;

VSSQ_PUBLIC extern const char vssq_messenger_config_k_ejabberd_url_virgil_chars[];

VSSQ_PUBLIC extern const vsc_str_t vssq_messenger_config_k_ejabberd_url_virgil;

//
//  Return size of 'vssq_messenger_config_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_config_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_config_init(vssq_messenger_config_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_config_cleanup(vssq_messenger_config_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_config_t *
vssq_messenger_config_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create object with required fields.
//
VSSQ_PUBLIC void
vssq_messenger_config_init_with(vssq_messenger_config_t *self, vsc_str_t base_url, vsc_str_t ejabberd_url);

//
//  Allocate class context and perform it's initialization.
//  Create object with required fields.
//
VSSQ_PUBLIC vssq_messenger_config_t *
vssq_messenger_config_new_with(vsc_str_t base_url, vsc_str_t ejabberd_url);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_config_delete(const vssq_messenger_config_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_config_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_config_destroy(vssq_messenger_config_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_config_t *
vssq_messenger_config_shallow_copy(vssq_messenger_config_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_config_t *
vssq_messenger_config_shallow_copy_const(const vssq_messenger_config_t *self);

//
//  Set path to the custom CA bundle.
//
VSSQ_PUBLIC void
vssq_messenger_config_set_ca_bundle(vssq_messenger_config_t *self, vsc_str_t ca_bundle);

VSSQ_PUBLIC vsc_str_t
vssq_messenger_config_base_url(const vssq_messenger_config_t *self);

VSSQ_PUBLIC vsc_str_t
vssq_messenger_config_ejabberd_url(const vssq_messenger_config_t *self);

VSSQ_PUBLIC vsc_str_t
vssq_messenger_config_ca_bundle(const vssq_messenger_config_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CONFIG_H_INCLUDED
//  @end
