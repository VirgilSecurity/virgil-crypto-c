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
//  Provide interface to for key marshaling.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_WRITER_H_INCLUDED
#define VSCF_KEY_WRITER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl.h"

#include <virgil/common/vsc_buffer.h>
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
//  Contains API requirements of the interface 'key writer'.
//
typedef struct vscf_key_writer_api_t vscf_key_writer_api_t;

//
//  Write public key object.
//
VSCF_PUBLIC vscf_error_t
vscf_key_writer_write_public_key(vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Write private key object.
//
VSCF_PUBLIC vscf_error_t
vscf_key_writer_write_private_key(vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Return length in bytes required to hold written public key.
//  Note, this is time consuming operation.
//  Note, estimation is approximate.
//
VSCF_PUBLIC size_t
vscf_key_writer_estimate_public_key_out_len(vscf_impl_t *impl);

//
//  Return length in bytes required to hold written private key.
//  Note, this is time consuming operation.
//  Note, estimation is approximate.
//
VSCF_PUBLIC size_t
vscf_key_writer_estimate_private_key_out_len(vscf_impl_t *impl);

//
//  Return key writer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_key_writer_api_t *
vscf_key_writer_api(vscf_impl_t *impl);

//
//  Check if given object implements interface 'key writer'.
//
VSCF_PUBLIC bool
vscf_key_writer_is_implemented(vscf_impl_t *impl);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_WRITER_H_INCLUDED
//  @end
