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

#ifndef VSCF_MESSAGE_INFO_CUSTOM_PARAMS_H_INCLUDED
#define VSCF_MESSAGE_INFO_CUSTOM_PARAMS_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error_ctx.h"
#include "vscf_list_key_value_node.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'message info custom params' context.
//
typedef struct vscf_message_info_custom_params_t vscf_message_info_custom_params_t;

//
//  Return size of 'vscf_message_info_custom_params_t'.
//
VSCF_PUBLIC size_t
vscf_message_info_custom_params_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_init(vscf_message_info_custom_params_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_cleanup(vscf_message_info_custom_params_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_message_info_custom_params_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_delete(vscf_message_info_custom_params_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_info_custom_params_new ()'.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_destroy(vscf_message_info_custom_params_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_message_info_custom_params_shallow_copy(vscf_message_info_custom_params_t *self);

//
//  Add custom parameter with integer value.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_int(vscf_message_info_custom_params_t *self, vsc_data_t key, int value);

//
//  Add custom parameter with UTF8 string value.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_string(vscf_message_info_custom_params_t *self, vsc_data_t key, vsc_data_t value);

//
//  Add custom parameter with octet string value.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_data(vscf_message_info_custom_params_t *self, vsc_data_t key, vsc_data_t value);

//
//  Remove all parameters.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_clear(vscf_message_info_custom_params_t *self);

//
//  Return custom parameter with integer value.
//
VSCF_PUBLIC int
vscf_message_info_custom_params_find_int(vscf_message_info_custom_params_t *self, vsc_data_t key,
        vscf_error_ctx_t *error);

//
//  Return custom parameter with UTF8 string value.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_custom_params_find_string(vscf_message_info_custom_params_t *self, vsc_data_t key,
        vscf_error_ctx_t *error);

//
//  Return custom parameter with octet string value.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_custom_params_find_data(vscf_message_info_custom_params_t *self, vsc_data_t key,
        vscf_error_ctx_t *error);

//
//  Return first param, or NULL if does not exist.
//
VSCF_PRIVATE const vscf_list_key_value_node_t *
vscf_message_info_custom_params_first_param(const vscf_message_info_custom_params_t *self);

//
//  Return next param, or NULL if does not exist.
//
VSCF_PRIVATE const vscf_list_key_value_node_t *
vscf_message_info_custom_params_next_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter's key.
//
VSCF_PRIVATE vsc_data_t
vscf_message_info_custom_params_param_key(const vscf_list_key_value_node_t *param);

//
//  Return true if given parameter holds an integer value.
//
VSCF_PRIVATE bool
vscf_message_info_custom_params_is_int_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter as an integer value.
//
VSCF_PRIVATE int
vscf_message_info_custom_params_as_int_value(const vscf_list_key_value_node_t *param);

//
//  Return true if given parameter holds a string value.
//
VSCF_PRIVATE bool
vscf_message_info_custom_params_is_string_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter as a string value.
//
VSCF_PRIVATE vsc_data_t
vscf_message_info_custom_params_as_string_value(const vscf_list_key_value_node_t *param);

//
//  Return true if given parameter holds a data value.
//
VSCF_PRIVATE bool
vscf_message_info_custom_params_is_data_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter as a data value.
//
VSCF_PRIVATE vsc_data_t
vscf_message_info_custom_params_as_data_value(const vscf_list_key_value_node_t *param);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_MESSAGE_INFO_CUSTOM_PARAMS_H_INCLUDED
//  @end
