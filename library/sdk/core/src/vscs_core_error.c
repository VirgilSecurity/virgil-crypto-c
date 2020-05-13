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


//  @description
// --------------------------------------------------------------------------
//  Error context.
//  Can be used for sequential operations, i.e. parsers, to accumulate error.
//  In this way operation is successful if all steps are successful, otherwise
//  last occurred error code can be obtained.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscs_core_error.h"
#include "vscs_core_memory.h"
#include "vscs_core_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return size of 'vscs_core_error_t'.
//
VSCS_CORE_PUBLIC size_t
vscs_core_error_ctx_size(void) {

    return sizeof(vscs_core_error_t);
}

//
//  Reset context to the "no error" state.
//
VSCS_CORE_PUBLIC void
vscs_core_error_reset(vscs_core_error_t *self) {

    VSCS_CORE_ASSERT_PTR(self);
    self->status = vscs_core_status_SUCCESS;
}

//
//  Update context with given status.
//  If status is "success" then do nothing.
//
VSCS_CORE_PRIVATE void
vscs_core_error_update(vscs_core_error_t *self, vscs_core_status_t status) {

    VSCS_CORE_ASSERT_PTR(self);

    if (status != vscs_core_status_SUCCESS) {
        self->status = status;
    }
}

//
//  Return true if status is not "success".
//
VSCS_CORE_PUBLIC bool
vscs_core_error_has_error(const vscs_core_error_t *self) {

    VSCS_CORE_ASSERT_PTR(self);
    return self->status != vscs_core_status_SUCCESS;
}

//
//  Return error code.
//
VSCS_CORE_PUBLIC vscs_core_status_t
vscs_core_error_status(const vscs_core_error_t *self) {

    VSCS_CORE_ASSERT_PTR(self);
    return self->status;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
