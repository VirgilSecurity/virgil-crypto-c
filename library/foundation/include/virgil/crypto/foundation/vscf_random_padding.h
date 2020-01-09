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
//  This module contains 'random padding' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_RANDOM_PADDING_H_INCLUDED
#define VSCF_RANDOM_PADDING_H_INCLUDED

#include "vscf_library.h"
#include "vscf_padding_params.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"
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
//  Handles implementation details.
//
typedef struct vscf_random_padding_t vscf_random_padding_t;

//
//  Return size of 'vscf_random_padding_t' type.
//
VSCF_PUBLIC size_t
vscf_random_padding_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_random_padding_impl(vscf_random_padding_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_random_padding_impl_const(const vscf_random_padding_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_random_padding_init(vscf_random_padding_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_random_padding_init()'.
//
VSCF_PUBLIC void
vscf_random_padding_cleanup(vscf_random_padding_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_random_padding_t *
vscf_random_padding_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_random_padding_new()'.
//
VSCF_PUBLIC void
vscf_random_padding_delete(vscf_random_padding_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_random_padding_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_random_padding_destroy(vscf_random_padding_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_random_padding_t *
vscf_random_padding_shallow_copy(vscf_random_padding_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_random_padding_use_random(vscf_random_padding_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_random_padding_take_random(vscf_random_padding_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_random_padding_release_random(vscf_random_padding_t *self);

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_random_padding_alg_id(const vscf_random_padding_t *self);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_random_padding_produce_alg_info(const vscf_random_padding_t *self);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_random_padding_restore_alg_info(vscf_random_padding_t *self, const vscf_impl_t *alg_info) VSCF_NODISCARD;

//
//  Set new padding parameters.
//
VSCF_PUBLIC void
vscf_random_padding_configure(vscf_random_padding_t *self, const vscf_padding_params_t *params);

//
//  Return length in bytes of a data with a padding.
//
VSCF_PUBLIC size_t
vscf_random_padding_padded_data_len(const vscf_random_padding_t *self, size_t data_len);

//
//  Return an actual number of padding in bytes.
//  Note, this method might be called right before "finish data processing".
//
VSCF_PUBLIC size_t
vscf_random_padding_len(const vscf_random_padding_t *self);

//
//  Return a maximum number of padding in bytes.
//
VSCF_PUBLIC size_t
vscf_random_padding_len_max(const vscf_random_padding_t *self);

//
//  Prepare the algorithm to process data.
//
VSCF_PUBLIC void
vscf_random_padding_start_data_processing(vscf_random_padding_t *self);

//
//  Only data length is needed to produce padding later.
//  Return data that should be further proceeded.
//
VSCF_PUBLIC vsc_data_t
vscf_random_padding_process_data(vscf_random_padding_t *self, vsc_data_t data);

//
//  Accomplish data processing and return padding.
//
VSCF_PUBLIC vscf_status_t
vscf_random_padding_finish_data_processing(vscf_random_padding_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Prepare the algorithm to process padded data.
//
VSCF_PUBLIC void
vscf_random_padding_start_padded_data_processing(vscf_random_padding_t *self);

//
//  Process padded data.
//  Return filtered data without padding.
//
VSCF_PUBLIC void
vscf_random_padding_process_padded_data(vscf_random_padding_t *self, vsc_data_t data, vsc_buffer_t *out);

//
//  Return length in bytes required hold output of the method
//  "finish padded data processing".
//
VSCF_PUBLIC size_t
vscf_random_padding_finish_padded_data_processing_out_len(const vscf_random_padding_t *self);

//
//  Accomplish padded data processing and return left data without a padding.
//
VSCF_PUBLIC vscf_status_t
vscf_random_padding_finish_padded_data_processing(vscf_random_padding_t *self, vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RANDOM_PADDING_H_INCLUDED
//  @end
