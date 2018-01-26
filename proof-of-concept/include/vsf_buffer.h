//  Copyright (c) 2015-2018 Virgil Security Inc.
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


#ifndef VSF_BUFFER_H_INCLUDED
#define VSF_BUFFER_H_INCLUDED

#include "vsf_library.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>


//  Opaque data types.
typedef struct _vsf_buffer_api_t vsf_buffer_api_t;

//  Return buffer.
VSF_PUBLIC const byte *
vsf_buffer_data (void *impl);

//  Return whole buffer size.
VSF_PUBLIC size_t
vsf_buffer_size (void *impl);

//  Return number of bytes that is actually are used within buffer.
VSF_PUBLIC size_t
vsf_buffer_used_size (void *impl);

//  Cleanup buffer.
VSF_PUBLIC void
vsf_buffer_cleanup (void *impl);

//  Release buffer.
//  Buffer should be cleaned manually.
//  If buffer was not defined, than do nothing.
VSF_PUBLIC void
vsf_buffer_release (void *impl);

//  Setup new buffer and keep ownership.
//  Precondition: object has no buffer.
VSF_PUBLIC void
vsf_buffer_use (void *impl, byte* buffer, size_t buffer_size);

//  Setup new buffer and transfer ownership.
//  Precondition: object has no buffer.
VSF_PUBLIC void
vsf_buffer_take (void *impl, byte** buffer, size_t buffer_size, vsf_dealloc_fn dealloc_fn);

//  Calculate required buffer size.
VSF_PUBLIC size_t
vsf_buffer_calc_size (void *impl);

//  Return buffer API, or NULL if hash API is not implemented.
VSF_PUBLIC const vsf_buffer_api_t*
vsf_buffer_api (void *impl);



#endif // VSF_BUFFER_H_INCLUDED
