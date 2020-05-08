//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  Encapsulates fixed characters array with variable effective length.
// --------------------------------------------------------------------------

#ifndef VSC_STR_BUFFER_H_INCLUDED
#define VSC_STR_BUFFER_H_INCLUDED

#include "vsc_library.h"
#include "vsc_str.h"
#include "vsc_str_buffer.h"

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
//  Handle 'str buffer' context.
//
typedef struct vsc_str_buffer_t vsc_str_buffer_t;

//
//  Return size of 'vsc_str_buffer_t'.
//
VSC_PUBLIC size_t
vsc_str_buffer_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSC_PUBLIC void
vsc_str_buffer_init(vsc_str_buffer_t *self);

//
//  Release all inner resources including class dependencies.
//
VSC_PUBLIC void
vsc_str_buffer_cleanup(vsc_str_buffer_t *self);

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_new(void);

//
//  Perform initialization of pre-allocated context.
//  Allocate inner character buffer of given capacity.
//
VSC_PUBLIC void
vsc_str_buffer_init_with_capacity(vsc_str_buffer_t *self, size_t capacity);

//
//  Allocate class context and perform it's initialization.
//  Allocate inner character buffer of given capacity.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_new_with_capacity(size_t capacity);

//
//  Perform initialization of pre-allocated context.
//  Allocate inner character buffer as copy of given string.
//
VSC_PUBLIC void
vsc_str_buffer_init_with_str(vsc_str_buffer_t *self, vsc_str_t str);

//
//  Allocate class context and perform it's initialization.
//  Allocate inner character buffer as copy of given string.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_new_with_str(vsc_str_t str);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSC_PUBLIC void
vsc_str_buffer_delete(vsc_str_buffer_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsc_str_buffer_new ()'.
//
VSC_PUBLIC void
vsc_str_buffer_destroy(vsc_str_buffer_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_shallow_copy(vsc_str_buffer_t *self);

//
//  Returns true if string length is zero.
//
VSC_PUBLIC bool
vsc_str_buffer_is_empty(const vsc_str_buffer_t *self);

//
//  Return true if strings are equal.
//
VSC_PUBLIC bool
vsc_str_buffer_equal(const vsc_str_buffer_t *self, const vsc_str_buffer_t *rhs);

//
//  Perform constant-time string comparison.
//  The time depends on the string length but not on the characters.
//  Return true if strings are equal.
//
VSC_PUBLIC bool
vsc_str_buffer_secure_equal(const vsc_str_buffer_t *self, const vsc_str_buffer_t *rhs);

//
//  Allocates inner characters array with a given capacity.
//  Precondition: characters array is initialized.
//  Precondition: characters array does not hold any character.
//  Postcondition: inner characters array is allocated.
//
VSC_PUBLIC void
vsc_str_buffer_alloc(vsc_str_buffer_t *self, size_t capacity);

//
//  Release inner characters array.
//
VSC_PUBLIC void
vsc_str_buffer_release(vsc_str_buffer_t *self);

//
//  Use given characters array as underlying string buffer.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any characters array.
//  Note, caller is responsible for given characters array deallocation.
//
VSC_PUBLIC void
vsc_str_buffer_use(vsc_str_buffer_t *self, char *chars, size_t chars_len);

//
//  Take given characters array as underlying string buffer.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any characters array.
//  Note, this class is responsible for given characters array deallocation.
//
VSC_PUBLIC void
vsc_str_buffer_take(vsc_str_buffer_t *self, char *chars, size_t chars_len, vsc_dealloc_fn dealloc_cb);

//
//  Mark string buffer as it holds sensitive data that must be erased
//  in a secure manner during destruction.
//
VSC_PUBLIC void
vsc_str_buffer_make_secure(vsc_str_buffer_t *self);

//
//  Returns true if string buffer is full.
//
VSC_PUBLIC bool
vsc_str_buffer_is_full(const vsc_str_buffer_t *self);

//
//  Returns true if string buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_str_buffer_is_valid(const vsc_str_buffer_t *self);

//
//  Returns underlying characters array.
//
VSC_PUBLIC const char *
vsc_str_buffer_chars(const vsc_str_buffer_t *self);

//
//  Returns underlying string buffer bytes as string.
//
VSC_PUBLIC vsc_str_t
vsc_str_buffer_str(const vsc_str_buffer_t *self);

//
//  Returns string buffer capacity.
//
VSC_PUBLIC size_t
vsc_str_buffer_capacity(const vsc_str_buffer_t *self);

//
//  Returns string buffer effective length - length of characters that are actually used.
//
VSC_PUBLIC size_t
vsc_str_buffer_len(const vsc_str_buffer_t *self);

//
//  Returns length of the characters array that are not in use yet.
//
VSC_PUBLIC size_t
vsc_str_buffer_unused_len(const vsc_str_buffer_t *self);

//
//  Returns writable pointer to the string buffer first element.
//
VSC_PUBLIC char *
vsc_str_buffer_begin(vsc_str_buffer_t *self);

//
//  Returns pointer to the first unused character in the string buffer.
//
VSC_PUBLIC char *
vsc_str_buffer_unused_chars(vsc_str_buffer_t *self);

//
//  Increase used characters by given length.
//
VSC_PUBLIC void
vsc_str_buffer_inc_used(vsc_str_buffer_t *self, size_t len);

//
//  Decrease used characters by given length.
//
VSC_PUBLIC void
vsc_str_buffer_dec_used(vsc_str_buffer_t *self, size_t len);

//
//  Copy string to the string buffer.
//
VSC_PUBLIC void
vsc_str_buffer_write_str(vsc_str_buffer_t *self, vsc_str_t str);

//
//  Copy string to the string buffer and reallocate if needed by coping.
//
//  Precondition: string buffer should be an owner of the underlying characters array.
//
//  Note, this operation can be slow if copy operation occurred.
//  Note, string buffer capacity is doubled.
//
VSC_PUBLIC void
vsc_str_buffer_append_str(vsc_str_buffer_t *self, vsc_str_t str);

//
//  Reset to the initial state.
//  After reset underlying characters array can be re-used.
//
VSC_PUBLIC void
vsc_str_buffer_reset(vsc_str_buffer_t *self);

//
//  Zeroing output buffer in secure manner.
//  And reset it to the initial state.
//
VSC_PUBLIC void
vsc_str_buffer_erase(vsc_str_buffer_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSC_STR_BUFFER_H_INCLUDED
//  @end
