//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
#include "vscp_library.h"
#include "vscp_error.h"
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
//  Handle 'pythia' context.
//
typedef struct vscp_pythia_t vscp_pythia_t;

//
//  Perform initialization of pre-allocated context.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_init(vscp_pythia_t* pythia_ctx);

//
//  Cleanup context.
//  This is a reverse action of the function 'vscp_pythia_init ()'.
//
VSCP_PUBLIC void
vscp_pythia_cleanup(vscp_pythia_t* pythia_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCP_PUBLIC vscp_pythia_t*
vscp_pythia_new(void);

//
//  Delete given context.
//  This is a reverse action of the function 'vscp_pythia_new ()'.
//
VSCP_PUBLIC void
vscp_pythia_delete(vscp_pythia_t* pythia_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscp_pythia_new ()'.
//
VSCP_PUBLIC void
vscp_pythia_destroy(vscp_pythia_t** pythia_ctx_ref);

//
//  Return length of the buffer needed to hold 'blinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinded_password_len(void);

//
//  Return length of the buffer needed to hold 'deblinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_deblinded_password_len(void);

//
//  Return length of the buffer needed to hold 'blinding secret'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinding_secret_len(void);

//
//  Blinds password. Turns password into a pseudo-random string.
//  This step is necessary to prevent 3rd-parties from knowledge of end user's password.
//
VSCP_PUBLIC void
vscp_pythia_blind(vscp_pythia_t* pythia_ctx, const byte* password, size_t pssword_len, byte* blinded_password,
        size_t blinded_password_len, byte* blinding_secret, size_t blinding_secret_len);

//
//  Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
//
VSCP_PUBLIC void
vscp_pythia_deblind(vscp_pythia_t* pythia_ctx, const byte* transformed_password, size_t transformed_pssword_len,
        const byte* blinding_secret, size_t blinding_secret_len, byte* deblinded_password,
        size_t deblinded_password_len);


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
