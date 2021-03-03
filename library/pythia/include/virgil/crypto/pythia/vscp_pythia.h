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
//  Provide Pythia implementation based on the Virgil Security.
// --------------------------------------------------------------------------

#ifndef VSCP_PYTHIA_H_INCLUDED
#define VSCP_PYTHIA_H_INCLUDED

#include "vscp_library.h"
#include "vscp_status.h"
#include "vscp_error.h"

#if !VSCP_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCP_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Performs global initialization of the pythia library.
//
//  Note, can be called multiple times, but actual configuration takes place once.
//  Note, this method is thread-safe.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_configure(void) VSCP_NODISCARD;

//
//  Performs global cleanup of the pythia library.
//
//  Note, can be called multiple times, but actual cleanup takes place once.
//  Note, should be called as many times, as "configure()" method called".
//  Note, this method is thread-safe.
//
VSCP_PUBLIC void
vscp_pythia_cleanup(void);

//
//  Return length of the buffer needed to hold 'blinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinded_password_buf_len(void);

//
//  Return length of the buffer needed to hold 'deblinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_deblinded_password_buf_len(void);

//
//  Return length of the buffer needed to hold 'blinding secret'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinding_secret_buf_len(void);

//
//  Return length of the buffer needed to hold 'transformation private key'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformation_private_key_buf_len(void);

//
//  Return length of the buffer needed to hold 'transformation public key'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformation_public_key_buf_len(void);

//
//  Return length of the buffer needed to hold 'transformed password'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformed_password_buf_len(void);

//
//  Return length of the buffer needed to hold 'transformed tweak'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformed_tweak_buf_len(void);

//
//  Return length of the buffer needed to hold 'proof value'.
//
VSCP_PUBLIC size_t
vscp_pythia_proof_value_buf_len(void);

//
//  Return length of the buffer needed to hold 'password update token'.
//
VSCP_PUBLIC size_t
vscp_pythia_password_update_token_buf_len(void);

//
//  Blinds password. Turns password into a pseudo-random string.
//  This step is necessary to prevent 3rd-parties from knowledge of end user's password.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_blind(vsc_data_t password, vsc_buffer_t *blinded_password, vsc_buffer_t *blinding_secret) VSCP_NODISCARD;

//
//  Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_deblind(vsc_data_t transformed_password, vsc_data_t blinding_secret,
        vsc_buffer_t *deblinded_password) VSCP_NODISCARD;

//
//  Computes transformation private and public key.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_compute_transformation_key_pair(vsc_data_t transformation_key_id, vsc_data_t pythia_secret,
        vsc_data_t pythia_scope_secret, vsc_buffer_t *transformation_private_key,
        vsc_buffer_t *transformation_public_key) VSCP_NODISCARD;

//
//  Transforms blinded password using transformation private key.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_transform(vsc_data_t blinded_password, vsc_data_t tweak, vsc_data_t transformation_private_key,
        vsc_buffer_t *transformed_password, vsc_buffer_t *transformed_tweak) VSCP_NODISCARD;

//
//  Generates proof that server possesses secret values that were used to transform password.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_prove(vsc_data_t transformed_password, vsc_data_t blinded_password, vsc_data_t transformed_tweak,
        vsc_data_t transformation_private_key, vsc_data_t transformation_public_key, vsc_buffer_t *proof_value_c,
        vsc_buffer_t *proof_value_u) VSCP_NODISCARD;

//
//  This operation allows client to verify that the output of transform() is correct,
//  assuming that client has previously stored transformation public key.
//
VSCP_PUBLIC bool
vscp_pythia_verify(vsc_data_t transformed_password, vsc_data_t blinded_password, vsc_data_t tweak,
        vsc_data_t transformation_public_key, vsc_data_t proof_value_c, vsc_data_t proof_value_u, vscp_error_t *error);

//
//  Rotates old transformation key to new transformation key and generates 'password update token',
//  that can update 'deblinded password'(s).
//
//  This action should increment version of the 'pythia scope secret'.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_get_password_update_token(vsc_data_t previous_transformation_private_key,
        vsc_data_t new_transformation_private_key, vsc_buffer_t *password_update_token) VSCP_NODISCARD;

//
//  Updates previously stored 'deblinded password' with 'password update token'.
//  After this call, 'transform()' called with new arguments will return corresponding values.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_update_deblinded_with_token(vsc_data_t deblinded_password, vsc_data_t password_update_token,
        vsc_buffer_t *updated_deblinded_password) VSCP_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCP_PYTHIA_H_INCLUDED
//  @end
