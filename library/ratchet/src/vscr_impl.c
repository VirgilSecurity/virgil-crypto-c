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
//  This module contains common functionality for all 'implementation' object.
//  It is also enumerate all available implementations within crypto libary.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_impl.h"
#include "vscr_api_private.h"
#include "vscr_impl_private.h"
#include "vscr_assert.h"

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
VSCR_PUBLIC const vscr_api_t *
vscr_impl_api(const vscr_impl_t *impl, vscr_api_tag_t api_tag) {

    VSCR_ASSERT_PTR(impl);
    VSCR_ASSERT_PTR(impl->info);

    if (impl->info->find_api_cb == NULL) {
        return NULL;
    }

    return impl->info->find_api_cb(api_tag);
}

//
//  Cleanup implementation object and it's dependencies.
//
VSCR_PUBLIC void
vscr_impl_cleanup(vscr_impl_t *impl) {

    VSCR_ASSERT_PTR (impl);
    VSCR_ASSERT_PTR (impl->info);
    VSCR_ASSERT_PTR (impl->info->self_cleanup_cb);

    impl->info->self_cleanup_cb (impl);
}

//
//  Delete implementation object and it's dependencies.
//
VSCR_PUBLIC void
vscr_impl_delete(vscr_impl_t *impl) {

    if (impl) {
        VSCR_ASSERT_PTR (impl->info);
        VSCR_ASSERT_PTR (impl->info->self_delete_cb);
        impl->info->self_delete_cb (impl);
    }
}

//
//  Destroy implementation object and it's dependencies.
//
VSCR_PUBLIC void
vscr_impl_destroy(vscr_impl_t **impl_ref) {

    VSCR_ASSERT_PTR (impl_ref);

    vscr_impl_t* impl = *impl_ref;
    *impl_ref = NULL;

    vscr_impl_delete (impl);
}

//
//  Copy implementation object by increasing reference counter.
//
VSCR_PUBLIC vscr_impl_t *
vscr_impl_shallow_copy(vscr_impl_t *impl) {

    VSCR_ASSERT_PTR (impl);

    ++impl->refcnt;

    return impl;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
