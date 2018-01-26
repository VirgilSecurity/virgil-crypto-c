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

#ifndef VSF_SHA256_H_INCLUDED
#define VSF_SHA256_H_INCLUDED

#include "vsf_library.h"

#ifdef __cplusplus
extern "C" {
#endif

// --------------------------------------------------------------------------
//  Constants and types.
// --------------------------------------------------------------------------

//  Public constants
enum {
    vsf_sha256_DIGEST_SIZE = 32,
    vsf_sha256_TYPE_SIZE_MAX = 3 * vsf_POINTER_SIZE + 144,
};

//  Opaque definition of implementation type.
typedef struct _vsf_sha256_t vsf_sha256_t;

// --------------------------------------------------------------------------
//  Lifecycle functions.
// --------------------------------------------------------------------------

//  Create new object by using default allocators.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new ();

//  Create new object by using given allocators.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new_ex (vsf_alloc_fn alloc_fn, vsf_dealloc_fn dealloc_fn);

//  Create new object in the given memory.
//  Caller is fully responsible for memory allocation and de-allocation.
//  Memory - is reference to the byte array.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new_in (byte **mem, size_t mem_size);

//  Create new object in the given memory.
//  Caller is fully responsible for allocation.
//  If de-allocation function is given, then it is used when object is destroyed.
//  Memory - is reference to the byte array.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new_in_ex (byte **mem_ref, size_t mem_size, vsf_dealloc_fn dealloc_fn);

//  Destroy given object. Reference is set to NULL.
//  It is safe to call it even if object was allocated in a static memory,
//  and de-allocation function was not defined. In this case object's
//  dependencies are destroyed and object itself is cleaned up.
VSF_PUBLIC void
vsf_sha256_destroy (vsf_sha256_t **impl_ref);


// --------------------------------------------------------------------------
//  Functions required by design.
// --------------------------------------------------------------------------

//  Erase inner state in a secure manner.
VSF_PUBLIC void
vsf_sha256_cleanup (vsf_sha256_t *impl);


// --------------------------------------------------------------------------
//  Functions that implements interface: hash.
// --------------------------------------------------------------------------

//  Start new hashing.
VSF_PUBLIC void
vsf_sha256_hash_start (vsf_sha256_t *impl);

//  Append given data to the hash.
VSF_PUBLIC void
vsf_sha256_hash_append (vsf_sha256_t *impl, const byte* data, size_t data_size);

//  Finalize hashing.
VSF_PUBLIC void
vsf_sha256_hash_finish (vsf_sha256_t *impl);

//  Stateless hashing.
VSF_PUBLIC void
vsf_sha256_hash_hash (const byte* data, size_t data_size, byte* digest, size_t digest_size);

// --------------------------------------------------------------------------
//  Functions that implements interface: buffer.
// --------------------------------------------------------------------------

//  Calculate required buffer size.
VSF_PUBLIC size_t
vsf_sha256_buffer_calc_size (void);

#ifdef __cplusplus
}
#endif

#endif // VSF_SHA256_H_INCLUDED
