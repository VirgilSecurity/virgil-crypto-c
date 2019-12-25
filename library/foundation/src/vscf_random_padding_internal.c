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


//  @description
// --------------------------------------------------------------------------
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_random_padding_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random_padding_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_padding.h"
#include "vscf_padding_api.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_random_padding_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the 'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RANDOM_PADDING,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_random_padding_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_random_padding_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_random_padding_restore_alg_info
};

//
//  Configuration of the interface API 'padding api'.
//
static const vscf_padding_api_t padding_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'padding' MUST be equal to the 'vscf_api_tag_PADDING'.
    //
    vscf_api_tag_PADDING,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_RANDOM_PADDING,
    //
    //  Set new padding parameters.
    //
    (vscf_padding_api_configure_fn)vscf_random_padding_configure,
    //
    //  Return length in bytes of a data with a padding.
    //
    (vscf_padding_api_padded_data_len_fn)vscf_random_padding_padded_data_len,
    //
    //  Return an actual number of padding in bytes.
    //  Note, this method might be called right before "finish data processing".
    //
    (vscf_padding_api_len_fn)vscf_random_padding_len,
    //
    //  Return a maximum number of padding in bytes.
    //
    (vscf_padding_api_len_max_fn)vscf_random_padding_len_max,
    //
    //  Prepare the algorithm to process data.
    //
    (vscf_padding_api_start_data_processing_fn)vscf_random_padding_start_data_processing,
    //
    //  Only data length is needed to produce padding later.
    //  Return data that should be further proceeded.
    //
    (vscf_padding_api_process_data_fn)vscf_random_padding_process_data,
    //
    //  Accomplish data processing and return padding.
    //
    (vscf_padding_api_finish_data_processing_fn)vscf_random_padding_finish_data_processing,
    //
    //  Prepare the algorithm to process padded data.
    //
    (vscf_padding_api_start_padded_data_processing_fn)vscf_random_padding_start_padded_data_processing,
    //
    //  Process padded data.
    //  Return filtered data without padding.
    //
    (vscf_padding_api_process_padded_data_fn)vscf_random_padding_process_padded_data,
    //
    //  Return length in bytes required hold output of the method
    //  "finish padded data processing".
    //
    (vscf_padding_api_finish_padded_data_processing_out_len_fn)vscf_random_padding_finish_padded_data_processing_out_len,
    //
    //  Accomplish padded data processing and return left data without a padding.
    //
    (vscf_padding_api_finish_padded_data_processing_fn)vscf_random_padding_finish_padded_data_processing
};

//
//  Compile-time known information about 'random padding' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_RANDOM_PADDING,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_random_padding_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_random_padding_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_random_padding_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_random_padding_init(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_random_padding_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_random_padding_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_random_padding_init()'.
//
VSCF_PUBLIC void
vscf_random_padding_cleanup(vscf_random_padding_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_random_padding_release_random(self);

    vscf_random_padding_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_random_padding_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_random_padding_t *
vscf_random_padding_new(void) {

    vscf_random_padding_t *self = (vscf_random_padding_t *) vscf_alloc(sizeof (vscf_random_padding_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_random_padding_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_random_padding_new()'.
//
VSCF_PUBLIC void
vscf_random_padding_delete(vscf_random_padding_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_random_padding_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_random_padding_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_random_padding_destroy(vscf_random_padding_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_random_padding_t *self = *self_ref;
    *self_ref = NULL;

    vscf_random_padding_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_random_padding_t *
vscf_random_padding_shallow_copy(vscf_random_padding_t *self) {

    // Proxy to the parent implementation.
    return (vscf_random_padding_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_random_padding_t' type.
//
VSCF_PUBLIC size_t
vscf_random_padding_impl_size(void) {

    return sizeof (vscf_random_padding_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_random_padding_impl(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_random_padding_impl_const(const vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_random_padding_use_random(vscf_random_padding_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_random_padding_take_random(vscf_random_padding_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_random_padding_release_random(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

static const vscf_api_t *
vscf_random_padding_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_PADDING:
            return (const vscf_api_t *) &padding_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
