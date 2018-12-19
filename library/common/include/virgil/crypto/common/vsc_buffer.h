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
//  Encapsulates fixed byte array with variable effective data length.
// --------------------------------------------------------------------------

#ifndef VSC_BUFFER_H_INCLUDED
#define VSC_BUFFER_H_INCLUDED

#include "vsc_library.h"
#include "vsc_data.h"
#include "vsc_buffer.h"

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
typedef struct vsc_buffer_t vsc_buffer_t;

//
//  Return size of 'vsc_buffer_t'.
//
VSC_PUBLIC size_t
vsc_buffer_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSC_PUBLIC void
vsc_buffer_init(vsc_buffer_t *buffer);

//
//  Release all inner resources including class dependencies.
//
VSC_PUBLIC void
vsc_buffer_cleanup(vsc_buffer_t *buffer);

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new(void);

//
//  Allocate context and underlying byte array.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_capacity(size_t capacity);

//
//  Create buffer with copied bytes from given data.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_data(vsc_data_t data);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSC_PUBLIC void
vsc_buffer_delete(vsc_buffer_t *buffer);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsc_buffer_new ()'.
//
VSC_PUBLIC void
vsc_buffer_destroy(vsc_buffer_t **buffer_ref);

//
//  Copy given class context by increasing reference counter.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_shallow_copy(vsc_buffer_t *buffer);

//
//  Returns true if buffer has no data written.
//
VSC_PUBLIC bool
vsc_buffer_is_empty(const vsc_buffer_t *buffer);

//
//  Return true if buffers are equal.
//
VSC_PUBLIC bool
vsc_buffer_equal(const vsc_buffer_t *buffer, const vsc_buffer_t *rhs);

//
//  Allocates inner buffer with a given capacity.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//  Postcondition: inner buffer is allocated.
//
VSC_PUBLIC void
vsc_buffer_alloc(vsc_buffer_t *buffer, size_t capacity);

//
//  Use given data as output buffer.
//  Client side is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_use(vsc_buffer_t *buffer, byte *bytes, size_t bytes_len);

//
//  Use given data as output buffer.
//  Buffer is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_take(vsc_buffer_t *buffer, byte *bytes, size_t bytes_len, vsc_dealloc_fn dealloc_cb);

//
//  Tell buffer that it holds sensitive that must be erased
//  in a secure manner during destruction.
//
VSC_PUBLIC void
vsc_buffer_make_secure(vsc_buffer_t *buffer);

//
//  Returns true if buffer full.
//
VSC_PUBLIC bool
vsc_buffer_is_full(const vsc_buffer_t *buffer);

//
//  Returns true if buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_buffer_is_valid(const vsc_buffer_t *buffer);

//
//  Returns underlying buffer bytes.
//
VSC_PUBLIC const byte *
vsc_buffer_bytes(const vsc_buffer_t *buffer);

//
//  Returns underlying buffer bytes as object.
//
VSC_PUBLIC vsc_data_t
vsc_buffer_data(const vsc_buffer_t *buffer);

//
//  Returns buffer capacity.
//
VSC_PUBLIC size_t
vsc_buffer_capacity(const vsc_buffer_t *buffer);

//
//  Returns buffer length - length of bytes actually used.
//
VSC_PUBLIC size_t
vsc_buffer_len(const vsc_buffer_t *buffer);

//
//  Returns length of the bytes that are not in use yet.
//
VSC_PUBLIC size_t
vsc_buffer_unused_len(const vsc_buffer_t *buffer);

//
//  Returns writable pointer to the buffer first element.
//
VSC_PUBLIC byte *
vsc_buffer_begin(vsc_buffer_t *buffer);

//
//  Returns pointer to the first unsed byte in the buffer.
//
VSC_PUBLIC byte *
vsc_buffer_unused_bytes(vsc_buffer_t *buffer);

//
//  Increase used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_inc_used(vsc_buffer_t *buffer, size_t len);

//
//  Decrease used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_dec_used(vsc_buffer_t *buffer, size_t len);

//
//  Copy null-terminated string to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_str(vsc_buffer_t *buffer, const char *str);

//
//  Copy data to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_data(vsc_buffer_t *buffer, vsc_data_t data);

//
//  Reset to the initial state.
//  After reset inner buffer can be re-used.
//
VSC_PUBLIC void
vsc_buffer_reset(vsc_buffer_t *buffer);

//
//  Zeroing buffer in secure manner.
//  And reset it to the initial state.
//
VSC_PUBLIC void
vsc_buffer_erase(vsc_buffer_t *buffer);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSC_BUFFER_H_INCLUDED
//  @end
