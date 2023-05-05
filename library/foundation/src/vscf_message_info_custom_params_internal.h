//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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

#ifndef VSCF_MESSAGE_INFO_CUSTOM_PARAMS_INTERNAL_H_INCLUDED
#define VSCF_MESSAGE_INFO_CUSTOM_PARAMS_INTERNAL_H_INCLUDED

#include "vscf_message_info_custom_params.h"
#include "vscf_list_key_value_node.h"
#include "vscf_error.h"

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
//  Add given node to the list ending.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_node(vscf_message_info_custom_params_t *self,
        vscf_list_key_value_node_t **node_ref);

//
//  Add given node to the list ending.
//
VSCF_PUBLIC const vscf_list_key_value_node_t *
vscf_message_info_custom_params_find_node(vscf_message_info_custom_params_t *self, vsc_data_t key, int value_tag,
        vscf_error_t *error);

//
//  Return first param, or NULL if does not exist.
//
VSCF_PUBLIC const vscf_list_key_value_node_t *
vscf_message_info_custom_params_first_param(const vscf_message_info_custom_params_t *self);

//
//  Return next param, or NULL if does not exist.
//
VSCF_PUBLIC const vscf_list_key_value_node_t *
vscf_message_info_custom_params_next_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter's key.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_custom_params_param_key(const vscf_list_key_value_node_t *param);

//
//  Return true if given parameter holds an integer value.
//
VSCF_PUBLIC bool
vscf_message_info_custom_params_is_int_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter as an integer value.
//
VSCF_PUBLIC int
vscf_message_info_custom_params_as_int_value(const vscf_list_key_value_node_t *param);

//
//  Return true if given parameter holds a string value.
//
VSCF_PUBLIC bool
vscf_message_info_custom_params_is_string_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter as a string value.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_custom_params_as_string_value(const vscf_list_key_value_node_t *param);

//
//  Return true if given parameter holds a data value.
//
VSCF_PUBLIC bool
vscf_message_info_custom_params_is_data_param(const vscf_list_key_value_node_t *param);

//
//  Return parameter as a data value.
//
VSCF_PUBLIC vsc_data_t
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
#endif // VSCF_MESSAGE_INFO_CUSTOM_PARAMS_INTERNAL_H_INCLUDED
//  @end
