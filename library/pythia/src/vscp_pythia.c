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


//  @description
// --------------------------------------------------------------------------
//  Provide Pythia implementation based on the Virgil Security.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscp_pythia.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'pythia' context.
//
struct vscp_pythia_t {
    size_t instances;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Return length of the buffer needed to hold 'blinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinded_password_len(void) {

    //  TODO: This is STUB. Implement me.
}

//
//  Return length of the buffer needed to hold 'deblinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_deblinded_password_len(void) {

    //  TODO: This is STUB. Implement me.
}

//
//  Return length of the buffer needed to hold 'blinding secret'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinding_secret_len(void) {

    //  TODO: This is STUB. Implement me.
}

//
//  Blinds password. Turns password into a pseudo-random string.
//  This step is necessary to prevent 3rd-parties from knowledge of end user's password.
//
VSCP_PUBLIC void
vscp_pythia_blind(const byte* password, size_t pssword_len, byte* blinded_password, size_t blinded_password_len,
        byte* blinding_secret, size_t blinding_secret_len) {

    //  TODO: This is STUB. Implement me.
}

//
//  Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
//
VSCP_PUBLIC void
vscp_pythia_deblind(const byte* transformed_password, size_t transformed_pssword_len, const byte* blinding_secret,
        size_t blinding_secret_len, byte* deblinded_password, size_t deblinded_password_len) {

    //  TODO: This is STUB. Implement me.
}
