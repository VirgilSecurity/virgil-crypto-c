//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Provide an interface to add and remove data padding.
// --------------------------------------------------------------------------

#ifndef VSCF_PADDING_H_INCLUDED
#define VSCF_PADDING_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_padding_params.h"
#include "vscf_status.h"
#include "vscf_api.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Contains API requirements of the interface 'padding'.
//
typedef struct vscf_padding_api_t vscf_padding_api_t;

//
//  Set new padding parameters.
//
VSCF_PUBLIC void
vscf_padding_configure(vscf_impl_t *impl, const vscf_padding_params_t *params);

//
//  Return length in bytes of a data with a padding.
//
VSCF_PUBLIC size_t
vscf_padding_padded_data_len(const vscf_impl_t *impl, size_t data_len);

//
//  Return an actual number of padding in bytes.
//  Note, this method might be called right before "finish data processing".
//
VSCF_PUBLIC size_t
vscf_padding_len(const vscf_impl_t *impl);

//
//  Return a maximum number of padding in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_len_max(const vscf_impl_t *impl);

//
//  Prepare the algorithm to process data.
//
VSCF_PUBLIC void
vscf_padding_start_data_processing(vscf_impl_t *impl);

//
//  Only data length is needed to produce padding later.
//  Return data that should be further proceeded.
//
VSCF_PUBLIC vsc_data_t
vscf_padding_process_data(vscf_impl_t *impl, vsc_data_t data);

//
//  Accomplish data processing and return padding.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_finish_data_processing(vscf_impl_t *impl, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Prepare the algorithm to process padded data.
//
VSCF_PUBLIC void
vscf_padding_start_padded_data_processing(vscf_impl_t *impl);

//
//  Process padded data.
//  Return filtered data without padding.
//
VSCF_PUBLIC void
vscf_padding_process_padded_data(vscf_impl_t *impl, vsc_data_t data, vsc_buffer_t *out);

//
//  Return length in bytes required hold output of the method
//  "finish padded data processing".
//
VSCF_PUBLIC size_t
vscf_padding_finish_padded_data_processing_out_len(const vscf_impl_t *impl);

//
//  Accomplish padded data processing and return left data without a padding.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_finish_padded_data_processing(vscf_impl_t *impl, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return padding API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_padding_api_t *
vscf_padding_api(const vscf_impl_t *impl);

//
//  Check if given object implements interface 'padding'.
//
VSCF_PUBLIC bool
vscf_padding_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_padding_api_tag(const vscf_padding_api_t *padding_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_PADDING_H_INCLUDED
//  @end
