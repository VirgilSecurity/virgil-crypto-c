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
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains 'ctr drbg' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_CTR_DRBG_H_INCLUDED
#define VSCF_CTR_DRBG_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_error.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Public integral constants.
//
enum {
    //
    //  The interval before reseed is performed by default.
    //
    vscf_ctr_drbg_RESEED_INTERVAL = 10000,
    //
    //  The amount of entropy used per seed by default.
    //
    vscf_ctr_drbg_ENTROPY_LEN = 48
};

//
//  Handles implementation details.
//
typedef struct vscf_ctr_drbg_impl_t vscf_ctr_drbg_impl_t;

//
//  Return size of 'vscf_ctr_drbg_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_ctr_drbg_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ctr_drbg_impl(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ctr_drbg_init(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ctr_drbg_init()'.
//
VSCF_PUBLIC void
vscf_ctr_drbg_cleanup(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ctr_drbg_impl_t *
vscf_ctr_drbg_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ctr_drbg_new()'.
//
VSCF_PUBLIC void
vscf_ctr_drbg_delete(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ctr_drbg_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ctr_drbg_destroy(vscf_ctr_drbg_impl_t **ctr_drbg_impl_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_ctr_drbg_impl_t *
vscf_ctr_drbg_copy(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Setup dependency to the interface 'entropy source' with shared ownership.
//
VSCF_PUBLIC vscf_error_t
vscf_ctr_drbg_use_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl, vscf_impl_t *entropy_source);

//
//  Setup dependency to the interface 'entropy source' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC vscf_error_t
vscf_ctr_drbg_take_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl, vscf_impl_t *entropy_source);

//
//  Release dependency to the interface 'entropy source'.
//
VSCF_PUBLIC void
vscf_ctr_drbg_release_entropy_source(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Setup entropy sources available for the current system.
//
VSCF_PUBLIC void
vscf_ctr_drbg_setup_defaults(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Force entropy to be gathered at the beginning of every call to
//  the (.class_ctr_drbg_method_random)() method.
//  Note, use this if your entropy source has sufficient throughput.
//
VSCF_PUBLIC void
vscf_ctr_drbg_enable_prediction_resistance(vscf_ctr_drbg_impl_t *ctr_drbg_impl);

//
//  Sets the reseed interval.
//  Default value is reseed interval.
//
VSCF_PUBLIC void
vscf_ctr_drbg_set_reseed_interval(vscf_ctr_drbg_impl_t *ctr_drbg_impl, size_t interval);

//
//  Sets the amount of entropy grabbed on each seed or reseed.
//  The default value is entropy len.
//
VSCF_PUBLIC void
vscf_ctr_drbg_set_entropy_len(vscf_ctr_drbg_impl_t *ctr_drbg_impl, size_t len);

//
//  Generate random bytes.
//
VSCF_PUBLIC vscf_error_t
vscf_ctr_drbg_random(vscf_ctr_drbg_impl_t *ctr_drbg_impl, size_t data_len, vsc_buffer_t *data);

//
//  Retreive new seed data from the entropy sources.
//
VSCF_PUBLIC vscf_error_t
vscf_ctr_drbg_reseed(vscf_ctr_drbg_impl_t *ctr_drbg_impl);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_CTR_DRBG_H_INCLUDED
//  @end
