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


//  @description
// --------------------------------------------------------------------------
//  This module contains common functionality for all 'implementation' object.
//  It is also enumerate all available implementations within crypto libary.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_impl.h"
#include "vscf_api_private.h"
#include "vscf_impl_private.h"
#include "vscf_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return 'API' object that is fulfiled with a meta information
//  specific to the given implementation object.
//  Or NULL if object does not implement requested 'API'.
//
VSCF_PUBLIC const vscf_api_t *
vscf_impl_api(const vscf_impl_t *impl, vscf_api_tag_t api_tag) {

    VSCF_ASSERT_PTR(impl);
    VSCF_ASSERT_PTR(impl->info);

    if (impl->info->find_api_cb == NULL) {
        return NULL;
    }

    return impl->info->find_api_cb(api_tag);
}

//
//  Cleanup implementation object and it's dependencies.
//
VSCF_PUBLIC void
vscf_impl_cleanup(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);
    VSCF_ASSERT_PTR (impl->info);
    VSCF_ASSERT_PTR (impl->info->self_cleanup_cb);

    impl->info->self_cleanup_cb (impl);
}

//
//  Delete implementation object and it's dependencies.
//
VSCF_PUBLIC void
vscf_impl_delete(vscf_impl_t *impl) {

    if (impl) {
        VSCF_ASSERT_PTR (impl->info);
        VSCF_ASSERT_PTR (impl->info->self_delete_cb);
        impl->info->self_delete_cb (impl);
    }
}

//
//  Destroy implementation object and it's dependencies.
//
VSCF_PUBLIC void
vscf_impl_destroy(vscf_impl_t **impl_ref) {

    VSCF_ASSERT_PTR (impl_ref);

    vscf_impl_t* impl = *impl_ref;
    *impl_ref = NULL;

    vscf_impl_delete (impl);
}

//
//  Copy implementation object by increasing reference counter.
//
VSCF_PUBLIC vscf_impl_t *
vscf_impl_shallow_copy(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    ++impl->refcnt;

    return impl;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
