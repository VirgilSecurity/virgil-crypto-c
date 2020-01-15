//
// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

#ifndef VSCF_FOUNDATION_PHP_H
#define VSCF_FOUNDATION_PHP_H


#if defined(_WIN32) || defined(__CYGWIN__)
#   if defined(VSCF_PHP_INTERNAL_BUILD)
#       ifdef __GNUC__
#           define VSCF_PHP_PUBLIC __attribute__ ((dllexport))
#       else
#           define VSCF_PHP_PUBLIC __declspec(dllexport)
#       endif
#   else
#       ifdef __GNUC__
#           define VSCF_PHP_PUBLIC __attribute__ ((dllimport))
#       else
#           define VSCF_PHP_PUBLIC __declspec(dllimport)
#       endif
#   endif
#   define VSC_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)
#       define VSCF_PHP_PUBLIC __attribute__ ((visibility ("default")))
#       define VSCF_PHP_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSCF_PHP_PRIVATE
#   endif
#endif

//
// Constants
//
VSCF_PHP_PUBLIC const char*
vscf_impl_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_recipient_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_recipient_info_list_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_password_recipient_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_password_recipient_info_list_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ecies_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_recipient_cipher_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_custom_params_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_provider_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_verifier_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_brainkey_client_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_brainkey_server_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_group_session_message_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_group_session_ticket_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_group_session_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_editor_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signer_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signer_info_list_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_footer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signed_data_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_footer_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_padding_params_t_php_res_name(void);

//
// Registered resources
//
VSCF_PHP_PUBLIC int
le_vscf_impl_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_recipient_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_recipient_info_list_t(void);

VSCF_PHP_PUBLIC int
le_vscf_password_recipient_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_password_recipient_info_list_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ecies_t(void);

VSCF_PHP_PUBLIC int
le_vscf_recipient_cipher_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_custom_params_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_provider_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_verifier_t(void);

VSCF_PHP_PUBLIC int
le_vscf_brainkey_client_t(void);

VSCF_PHP_PUBLIC int
le_vscf_brainkey_server_t(void);

VSCF_PHP_PUBLIC int
le_vscf_group_session_message_t(void);

VSCF_PHP_PUBLIC int
le_vscf_group_session_ticket_t(void);

VSCF_PHP_PUBLIC int
le_vscf_group_session_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_editor_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signer_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signer_info_list_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_footer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signed_data_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_footer_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_padding_params_t(void);

#endif // VSCF_FOUNDATION_PHP_H 
