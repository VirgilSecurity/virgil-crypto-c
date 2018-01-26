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

#include "vsf_sha256.h"

#include "vsf_hash_api.h"
#include "vsf_impl_info.h"
#include "vsf_buffer_api.h"
#include "vsf_memory.h"
#include "vsf_assert.h"

#include <mbedtls/sha256.h>


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//   Private functions required by design.
// --------------------------------------------------------------------------

//  Perform constraints check during compilation.
VSF_PRIVATE static void
vsf_sha256_hash_static_check (void);

//  Init implementation specific contexts.
VSF_PRIVATE static void
vsf_sha256_init (vsf_sha256_t *impl);

//  Check that implementation specific contexts are initialized,
//  and ready for use,
VSF_PRIVATE static void
vsf_sha256_assert_is_init (vsf_sha256_t *impl);


// --------------------------------------------------------------------------
//   Private functions that implement interface: buffer.
// --------------------------------------------------------------------------

//  Return object buffer.
VSF_PRIVATE static vsf_buffer_t *
vsf_sha256_buffer_buffer (vsf_sha256_t *impl);


// --------------------------------------------------------------------------
//  Callback routing configuration.
// --------------------------------------------------------------------------

//  Interface 'hash' configuration.
static vsf_hash_api_t hash_api = {
    //  API unique identifier, MUST be first in the structure.
    //  For hash algorithms MUST be set to the "vsf_api_tag_HASH".
    vsf_api_tag_HASH,

    //  Start new hashing.
    (vsf_hash_api_start_fn) vsf_sha256_hash_start,

    //  Append given data to the hash.
    (vsf_hash_api_append_fn) vsf_sha256_hash_append,

    //  Finalize hashing.
    (vsf_hash_api_finish_fn) vsf_sha256_hash_finish,

    //  Stateless hashing.
    vsf_sha256_hash_hash,

    //  Check algorithm runtime availability.
    //  Always available.
    NULL,

    //  Output digest size in bytes.
    vsf_sha256_DIGEST_SIZE
};

//  Interface 'buffer' configuration.
static vsf_buffer_api_t buffer_api = {
    //  API unique identifier, MUST be first in the structure.
    //  For algorithms that support buffer MUST be set to the "vsf_api_tag_BUFFER".
    vsf_api_tag_BUFFER,

    //  Return buffer.
    (vsf_buffer_api_buffer_fn) vsf_sha256_buffer_buffer,

    //  Calculate required buffer size.
    (vsf_buffer_api_calc_size_fn) vsf_sha256_buffer_calc_size,
};

//  List of implemented interfaces.
//  Can be speed optimized by provide array instead of list.
//  Each array position is correspond to the vsf_api_tag_t
//  Drawback: static size will be increased.
static const void * const sha256_api_list[] = {
    &hash_api,
    &buffer_api,
    NULL
};


//  Implementation details known at compile time.
static vsf_impl_info_t sha256_impl_info = {
    // Implementation unique identifier, MUST be first in the structure.
    vsf_impl_tag_HASH_SHA256,

    //  NULL terminated List of the implemented interfaces.
    //  MUST be second in the structure.
    sha256_api_list,

    //  Erase inner state in a secure manner.
    (vsf_impl_cleanup_fn) vsf_sha256_cleanup,

    //  Self destruction, according to destruction policy.
    (vsf_impl_destroy_fn) vsf_sha256_destroy,
};


// --------------------------------------------------------------------------
//  Context types.
// --------------------------------------------------------------------------

//  Implementation type.
struct _vsf_sha256_t {
    //  Meta information about implementation. Must be FIRST in the structure.
    vsf_impl_info_t* info;

    //  De-allocation function that SHOULD be used to deallocate this structure.
    void (*dealloc_fn) (void *self);

    //  Mixin 'buffer' context.
    vsf_buffer_t output_buffer;

    //  Underlying context that handles actual algorithm implementation.
    mbedtls_sha256_context hash_ctx;
};


// --------------------------------------------------------------------------
//  Lifecycle functions.
// --------------------------------------------------------------------------

//  Create new object, use default allocators.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new (void) {
    return vsf_sha256_new_ex (vsf_alloc, vsf_dealloc);
}

//  Create new object, use given allocators.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new_ex (vsf_alloc_fn alloc_fn, vsf_dealloc_fn dealloc_fn) {
    VSF_ASSERT (alloc_fn);
    VSF_ASSERT (dealloc_fn);

    byte *impl = (byte *) alloc_fn (sizeof (vsf_sha256_t));
    VSF_ASSERT (impl);

    return vsf_sha256_new_in_ex (&impl, sizeof (vsf_sha256_t), dealloc_fn);
}

//  Create new object in the given memory.
//  Caller is fully responsible for memory allocation and de-allocation.
//  Memory - is reference to the byte array.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new_in (byte **mem_ref, size_t mem_size) {
    return vsf_sha256_new_in_ex (mem_ref, mem_size, NULL);
}

//  Create new object in the given memory.
//  Caller is fully responsible for allocation.
//  If de-allocation function is given, then it is used when object is destroyed.
//  Memory - is reference to the byte array.
VSF_PUBLIC vsf_sha256_t *
vsf_sha256_new_in_ex (byte **mem_ref, size_t mem_size, vsf_dealloc_fn dealloc_fn) {

    VSF_ASSERT (mem_ref);
    byte* mem = *mem_ref;
    VSF_ASSERT (mem);

    VSF_ASSERT (mem_size >= sizeof (vsf_sha256_t));
    *mem_ref += sizeof (vsf_sha256_t);

    vsf_sha256_t *impl = (vsf_sha256_t *) mem;

    impl->info = &sha256_impl_info;
    impl->dealloc_fn = dealloc_fn;

    vsf_sha256_init (impl);

    return impl;
}

//  Destroy given object. Reference is set to NULL.
VSF_PUBLIC void
vsf_sha256_destroy (vsf_sha256_t **impl_ref) {
    VSF_ASSERT (impl_ref);

    vsf_sha256_t *impl = *impl_ref;
    if (impl == NULL) {
        return;
    }

    //  Cleanup interface contexts
    vsf_sha256_cleanup (impl);

    //  Release mixins
    vsf_buffer_release (impl);

    //  Destroy dependencies


    //  Dealloc self
    VSF_ASSERT (impl->info);
    if (impl->dealloc_fn) {
        impl->dealloc_fn (impl);
    }

    *impl_ref = NULL;
}


// --------------------------------------------------------------------------
//  End of generated section
// --------------------------------------------------------------------------
// @end


// --------------------------------------------------------------------------
//  Functions that implements interface: hash.
// --------------------------------------------------------------------------

//  Start new hashing.
VSF_PUBLIC void
vsf_sha256_hash_start (vsf_sha256_t *impl) {
    vsf_sha256_assert_is_init (impl);
    int is224 = 0;
    mbedtls_sha256_starts (&impl->hash_ctx, is224);
}

//  Append given data to the hash.
VSF_PUBLIC void
vsf_sha256_hash_append (vsf_sha256_t *impl, const byte* data, size_t data_size) {
    vsf_sha256_assert_is_init (impl);
    mbedtls_sha256_update (&impl->hash_ctx, data, data_size);
}

//  Finalize hashing.
VSF_PUBLIC void
vsf_sha256_hash_finish (vsf_sha256_t *impl) {
    vsf_sha256_assert_is_init (impl);

    if (impl->output_buffer.data == NULL) {
        impl->output_buffer.data = vsf_alloc(vsf_sha256_DIGEST_SIZE);
        impl->output_buffer.size = vsf_sha256_DIGEST_SIZE;
        impl->output_buffer.dealloc_fn = vsf_dealloc;
    }
    VSF_ASSERT_OPT (impl->output_buffer.data != NULL);
    VSF_ASSERT_OPT (impl->output_buffer.size >= vsf_sha256_DIGEST_SIZE);

    mbedtls_sha256_finish (&impl->hash_ctx, impl->output_buffer.data);
    impl->output_buffer.used_size = vsf_sha256_DIGEST_SIZE;
}

//  Stateless hashing.
VSF_PUBLIC void
vsf_sha256_hash_hash (const byte* data, size_t data_size, byte* digest, size_t digest_size) {
    VSF_ASSERT (data);
    VSF_ASSERT (digest);
    VSF_ASSERT_OPT (digest_size >= vsf_sha256_DIGEST_SIZE);
    const int is224 = 0;
    mbedtls_sha256 (data, data_size, digest, is224);
}


// --------------------------------------------------------------------------
// Functions that implements interface: buffer.
// --------------------------------------------------------------------------

//  Retrun buffer
VSF_PRIVATE vsf_buffer_t *
vsf_sha256_buffer_buffer (vsf_sha256_t *impl) {
    VSF_ASSERT (impl);
    return &impl->output_buffer;
}

//  Calculate required buffer size.
VSF_PUBLIC size_t
vsf_sha256_buffer_calc_size (void) {
    return vsf_sha256_DIGEST_SIZE;
}


// --------------------------------------------------------------------------
//  Functions required by design.
// --------------------------------------------------------------------------

//  Perform constraints check during compilation.
VSF_PRIVATE static
void vsf_sha256_hash_static_check (void) {
    VSF_ASSERT_STATIC (sizeof (vsf_sha256_t) <= vsf_sha256_TYPE_SIZE_MAX);
}

//  Init implementation specific contexts.
VSF_PRIVATE static
void vsf_sha256_init (vsf_sha256_t *impl) {
    VSF_ASSERT (impl);

    mbedtls_sha256_init (&impl->hash_ctx);

    vsf_zeroize (&impl->output_buffer, sizeof (vsf_buffer_t));
}

//  Check that implementation specific contexts are initialized,
//  and ready for use,
VSF_PRIVATE static void
vsf_sha256_assert_is_init (vsf_sha256_t *impl) {
    VSF_ASSERT (impl);
    VSF_ASSERT (impl->info);
    VSF_ASSERT (impl->info == &sha256_impl_info);
}

//  Erase inner state in a secure manner.
VSF_PUBLIC void
vsf_sha256_cleanup (vsf_sha256_t *impl) {
    vsf_sha256_assert_is_init (impl);
    mbedtls_sha256_free (&impl->hash_ctx);
    vsf_buffer_cleanup (impl);
}
