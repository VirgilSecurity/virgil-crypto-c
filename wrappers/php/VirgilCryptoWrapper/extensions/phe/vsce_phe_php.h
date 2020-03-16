//
// Copyright (C) 2015-2020 Virgil Security, Inc.
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

#ifndef VSCE_PHP_PHE_PHP_H_INCLUDED
#define VSCE_PHP_PHE_PHP_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif


#if defined(_WIN32) || defined(__CYGWIN__)
#   if VSCE_PHP_SHARED_LIBRARY
#       if defined(VSCE_PHP_INTERNAL_BUILD)
#           ifdef __GNUC__
#               define VSCE_PHP_PUBLIC __attribute__ ((dllexport))
#           else
#               define VSCE_PHP_PUBLIC __declspec(dllexport)
#           endif
#       else
#           ifdef __GNUC__
#               define VSCE_PHP_PUBLIC __attribute__ ((dllimport))
#           else
#               define VSCE_PHP_PUBLIC __declspec(dllimport)
#           endif
#       endif
#   else
#       define VSCE_PHP_PUBLIC
#   endif
#   define VSCE_PHP_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)
#       define VSCE_PHP_PUBLIC __attribute__ ((visibility ("default")))
#       define VSCE_PHP_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSCE_PHP_PRIVATE
#   endif
#endif

//
// Constants
//
VSCE_PHP_PUBLIC const char*
vsce_phe_server_t_php_res_name(void);

VSCE_PHP_PUBLIC const char*
vsce_phe_client_t_php_res_name(void);

VSCE_PHP_PUBLIC const char*
vsce_phe_cipher_t_php_res_name(void);

VSCE_PHP_PUBLIC const char*
vsce_uokms_client_t_php_res_name(void);

VSCE_PHP_PUBLIC const char*
vsce_uokms_server_t_php_res_name(void);

VSCE_PHP_PUBLIC const char*
vsce_uokms_wrap_rotation_t_php_res_name(void);

//
// Registered resources
//
VSCE_PHP_PUBLIC int
le_vsce_phe_server_t(void);

VSCE_PHP_PUBLIC int
le_vsce_phe_client_t(void);

VSCE_PHP_PUBLIC int
le_vsce_phe_cipher_t(void);

VSCE_PHP_PUBLIC int
le_vsce_uokms_client_t(void);

VSCE_PHP_PUBLIC int
le_vsce_uokms_server_t(void);

VSCE_PHP_PUBLIC int
le_vsce_uokms_wrap_rotation_t(void);

#ifdef __cplusplus
}
#endif

#endif // VSCE_PHP_PHE_PHP_H_INCLUDED
