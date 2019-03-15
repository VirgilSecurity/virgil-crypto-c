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
//  Error context.
//  Can be used for sequential operations, i.e. parsers, to accumulate error.
//  In this way operation is successful if all steps are successful, otherwise
//  last occurred error code can be obtained.
// --------------------------------------------------------------------------

#ifndef VSCF_ERROR_H_INCLUDED
#define VSCF_ERROR_H_INCLUDED

#include "vscf_library.h"
#include "vscf_status.h"

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
//  Perform update only if context defined, otherwise log error.
//
#define VSCF_ERROR_SAFE_UPDATE(CTX, ERR)                            \
    do {                                                            \
        if (NULL != (CTX)) {                                        \
            vscf_error_update ((CTX), (ERR));                       \
        } else {                                                    \
            /* TODO: Log this error, when logging will be added. */ \
        }                                                           \
    } while (false)

//
//  Handle 'error' context.
//
typedef struct vscf_error_t vscf_error_t;
struct vscf_error_t {
    vscf_status_t status;
};

//
//  Return size of 'vscf_error_t'.
//
VSCF_PUBLIC size_t
vscf_error_ctx_size(void);

//
//  Reset context to the "no error" state.
//
VSCF_PUBLIC void
vscf_error_reset(vscf_error_t *self);

//
//  Update context with given status.
//  If status is "success" then do nothing.
//
VSCF_PRIVATE void
vscf_error_update(vscf_error_t *self, vscf_status_t status);

//
//  Return true if status is not "success".
//
VSCF_PUBLIC bool
vscf_error_has_error(const vscf_error_t *self);

//
//  Return error code.
//
VSCF_PUBLIC vscf_status_t
vscf_error_status(const vscf_error_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ERROR_H_INCLUDED
//  @end
