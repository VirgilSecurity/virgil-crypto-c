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
//  Handle meta information about footer.
// --------------------------------------------------------------------------

#ifndef VSCF_FOOTER_INFO_H_INCLUDED
#define VSCF_FOOTER_INFO_H_INCLUDED

#include "vscf_library.h"
#include "vscf_signed_data_info.h"

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
//  Handle 'footer info' context.
//
typedef struct vscf_footer_info_t vscf_footer_info_t;

//
//  Return size of 'vscf_footer_info_t'.
//
VSCF_PUBLIC size_t
vscf_footer_info_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_footer_info_init(vscf_footer_info_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_footer_info_cleanup(vscf_footer_info_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_footer_info_t *
vscf_footer_info_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_footer_info_delete(vscf_footer_info_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_footer_info_new ()'.
//
VSCF_PUBLIC void
vscf_footer_info_destroy(vscf_footer_info_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_footer_info_t *
vscf_footer_info_shallow_copy(vscf_footer_info_t *self);

//
//  Retrun true if signed data info present.
//
VSCF_PUBLIC bool
vscf_footer_info_has_signed_data_info(const vscf_footer_info_t *self);

//
//  Setup signed data info.
//
VSCF_PRIVATE void
vscf_footer_info_set_signed_data_info(vscf_footer_info_t *self, vscf_signed_data_info_t **signed_data_info_ref);

//
//  Return signed data info.
//
VSCF_PUBLIC const vscf_signed_data_info_t *
vscf_footer_info_signed_data_info(const vscf_footer_info_t *self);

//
//  Return mutable signed data info.
//
VSCF_PRIVATE vscf_signed_data_info_t *
vscf_footer_info_signed_data_info_m(vscf_footer_info_t *self);

//
//  Remove signed data info.
//
VSCF_PRIVATE void
vscf_footer_info_remove_signed_data_info(vscf_footer_info_t *self);

//
//  Set data size.
//
VSCF_PUBLIC void
vscf_footer_info_set_data_size(vscf_footer_info_t *self, size_t data_size);

//
//  Return data size.
//
VSCF_PUBLIC size_t
vscf_footer_info_data_size(const vscf_footer_info_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_FOOTER_INFO_H_INCLUDED
//  @end
