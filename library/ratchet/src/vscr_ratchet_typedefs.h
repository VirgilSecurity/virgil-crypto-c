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


//  @description
// --------------------------------------------------------------------------
//  Typedefs for ratchet.
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_TYPEDEFS_H_INCLUDED
#define VSCR_RATCHET_TYPEDEFS_H_INCLUDED

#include <stdint.h>

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

#ifndef VSCR_RATCHET_PUBLIC_KEY_T_32__DEFINED
#define VSCR_RATCHET_PUBLIC_KEY_T_32__DEFINED
    typedef uint8_t vscr_ratchet_public_key_t[32];
#endif // VSCR_RATCHET_PUBLIC_KEY_T_32__DEFINED

#ifndef VSCR_RATCHET_PRIVATE_KEY_T_32__DEFINED
#define VSCR_RATCHET_PRIVATE_KEY_T_32__DEFINED
    typedef uint8_t vscr_ratchet_private_key_t[32];
#endif // VSCR_RATCHET_PRIVATE_KEY_T_32__DEFINED

#ifndef VSCR_RATCHET_SYMMETRIC_KEY_T_32__DEFINED
#define VSCR_RATCHET_SYMMETRIC_KEY_T_32__DEFINED
    typedef uint8_t vscr_ratchet_symmetric_key_t[32];
#endif // VSCR_RATCHET_SYMMETRIC_KEY_T_32__DEFINED

#ifndef VSCR_RATCHET_PARTICIPANT_ID_T_32__DEFINED
#define VSCR_RATCHET_PARTICIPANT_ID_T_32__DEFINED
    typedef uint8_t vscr_ratchet_participant_id_t[32];
#endif // VSCR_RATCHET_PARTICIPANT_ID_T_32__DEFINED

#ifndef VSCR_RATCHET_SESSION_ID_T_32__DEFINED
#define VSCR_RATCHET_SESSION_ID_T_32__DEFINED
    typedef uint8_t vscr_ratchet_session_id_t[32];
#endif // VSCR_RATCHET_SESSION_ID_T_32__DEFINED


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_TYPEDEFS_H_INCLUDED
//  @end
