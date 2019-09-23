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
//  Class 'buffer' types definition.
// --------------------------------------------------------------------------

#ifndef VSC_BUFFER_DEFS_H_INCLUDED
#define VSC_BUFFER_DEFS_H_INCLUDED

#include "vsc_library.h"
#include "vsc_atomic.h"

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
//  Handle 'buffer' context.
//
struct vsc_buffer_t {
    //
    //  Function do deallocate self context.
    //
    vsc_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    VSC_ATOMIC size_t refcnt;
    //
    //  Function do deallocate underlying byte array.
    //
    vsc_dealloc_fn bytes_dealloc_cb;
    //
    //  Underlying byte array.
    //
    byte *bytes;
    //
    //  Byte array capacity - total allocated bytes.
    //
    size_t capacity;
    //
    //  Byte array length - actually used bytes from the beginning.
    //
    size_t len;
    //
    //  Defines that buffer holds sensitive data that must be erased
    //  in a secure manner.
    //
    bool is_secure;
    //
    //  Defines that buffer is the owner of the underlying bytes.
    //
    bool is_owner;
    //
    //  Defines that buffer is in the reverse mode.
    //  This means that written data is located from the buffer ending.
    //
    bool is_reverse;
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
#endif // VSC_BUFFER_DEFS_H_INCLUDED
//  @end
