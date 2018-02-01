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


//  @description
// --------------------------------------------------------------------------
//  Provides interface to the key derivation function (KDF) algorithms.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_kdf.h"
//  @end

#include <stdbool.h>
#include "vsf_impl_private.h"
#include "vsf_kdf_api.h"
#include "vsf_assert.h"

//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Generated functions.
// ==========================================================================

//  Calculate hash over given data.
VSF_PUBLIC const byte *
vsf_kdf_derive (vsf_impl_t *impl, const byte *data) {

    VSF_ASSERT (impl);
    VSF_ASSERT (data);

    const vsf_kdf_api_t *kdf = vsf_kdf_api (impl);
    VSF_ASSERT (kdf);

    VSF_ASSERT (kdf->derive_cb);
    return kdf->derive_cb (impl, data);
}

//  Return kdf API, or NULL if it is not implemented.
VSF_PUBLIC const vsf_kdf_api_t *
vsf_kdf_api (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return (vsf_kdf_api_t *) vsf_impl_api (impl, vsf_api_tag_KDF);
}

//  Check if given object implements interface 'kdf'.
VSF_PUBLIC bool
vsf_kdf_is_implemented (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return vsf_impl_api (impl, vsf_api_tag_KDF) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
