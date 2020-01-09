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
//  Interface 'padding' API.
// --------------------------------------------------------------------------

#ifndef VSCF_PADDING_API_H_INCLUDED
#define VSCF_PADDING_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_padding_params.h"
#include "vscf_status.h"

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
//  Callback. Set new padding parameters.
//
typedef void (*vscf_padding_api_configure_fn)(vscf_impl_t *impl, const vscf_padding_params_t *params);

//
//  Callback. Return length in bytes of a data with a padding.
//
typedef size_t (*vscf_padding_api_padded_data_len_fn)(const vscf_impl_t *impl, size_t data_len);

//
//  Callback. Return an actual number of padding in bytes.
//          Note, this method might be called right before "finish data processing".
//
typedef size_t (*vscf_padding_api_len_fn)(const vscf_impl_t *impl);

//
//  Callback. Return a maximum number of padding in bytes.
//
typedef size_t (*vscf_padding_api_len_max_fn)(const vscf_impl_t *impl);

//
//  Callback. Prepare the algorithm to process data.
//
typedef void (*vscf_padding_api_start_data_processing_fn)(vscf_impl_t *impl);

//
//  Callback. Only data length is needed to produce padding later.
//          Return data that should be further proceeded.
//
typedef vsc_data_t (*vscf_padding_api_process_data_fn)(vscf_impl_t *impl, vsc_data_t data);

//
//  Callback. Accomplish data processing and return padding.
//
typedef vscf_status_t (*vscf_padding_api_finish_data_processing_fn)(vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Callback. Prepare the algorithm to process padded data.
//
typedef void (*vscf_padding_api_start_padded_data_processing_fn)(vscf_impl_t *impl);

//
//  Callback. Process padded data.
//          Return filtered data without padding.
//
typedef void (*vscf_padding_api_process_padded_data_fn)(vscf_impl_t *impl, vsc_data_t data, vsc_buffer_t *out);

//
//  Callback. Return length in bytes required hold output of the method
//          "finish padded data processing".
//
typedef size_t (*vscf_padding_api_finish_padded_data_processing_out_len_fn)(const vscf_impl_t *impl);

//
//  Callback. Accomplish padded data processing and return left data without a padding.
//
typedef vscf_status_t (*vscf_padding_api_finish_padded_data_processing_fn)(vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Contains API requirements of the interface 'padding'.
//
struct vscf_padding_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'padding' MUST be equal to the 'vscf_api_tag_PADDING'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Set new padding parameters.
    //
    vscf_padding_api_configure_fn configure_cb;
    //
    //  Return length in bytes of a data with a padding.
    //
    vscf_padding_api_padded_data_len_fn padded_data_len_cb;
    //
    //  Return an actual number of padding in bytes.
    //  Note, this method might be called right before "finish data processing".
    //
    vscf_padding_api_len_fn len_cb;
    //
    //  Return a maximum number of padding in bytes.
    //
    vscf_padding_api_len_max_fn len_max_cb;
    //
    //  Prepare the algorithm to process data.
    //
    vscf_padding_api_start_data_processing_fn start_data_processing_cb;
    //
    //  Only data length is needed to produce padding later.
    //  Return data that should be further proceeded.
    //
    vscf_padding_api_process_data_fn process_data_cb;
    //
    //  Accomplish data processing and return padding.
    //
    vscf_padding_api_finish_data_processing_fn finish_data_processing_cb;
    //
    //  Prepare the algorithm to process padded data.
    //
    vscf_padding_api_start_padded_data_processing_fn start_padded_data_processing_cb;
    //
    //  Process padded data.
    //  Return filtered data without padding.
    //
    vscf_padding_api_process_padded_data_fn process_padded_data_cb;
    //
    //  Return length in bytes required hold output of the method
    //  "finish padded data processing".
    //
    vscf_padding_api_finish_padded_data_processing_out_len_fn finish_padded_data_processing_out_len_cb;
    //
    //  Accomplish padded data processing and return left data without a padding.
    //
    vscf_padding_api_finish_padded_data_processing_fn finish_padded_data_processing_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_PADDING_API_H_INCLUDED
//  @end
