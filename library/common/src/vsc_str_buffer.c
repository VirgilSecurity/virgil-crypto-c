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


//  @description
// --------------------------------------------------------------------------
//  Encapsulates fixed characters array with variable effective length.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsc_str_buffer.h"
#include "vsc_memory.h"
#include "vsc_assert.h"
#include "vsc_str_buffer_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsc_str_buffer_init() is called.
//  Note, that context is already zeroed.
//
static void
vsc_str_buffer_init_ctx(vsc_str_buffer_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_str_buffer_cleanup_ctx(vsc_str_buffer_t *self);

//
//  Allocate inner character buffer of given capacity.
//
static void
vsc_str_buffer_init_ctx_with_capacity(vsc_str_buffer_t *self, size_t capacity);

//
//  Allocate inner character buffer as copy of given string.
//
static void
vsc_str_buffer_init_ctx_with_str(vsc_str_buffer_t *self, vsc_str_t str);

//
//  Return size of 'vsc_str_buffer_t'.
//
VSC_PUBLIC size_t
vsc_str_buffer_ctx_size(void) {

    return sizeof(vsc_str_buffer_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSC_PUBLIC void
vsc_str_buffer_init(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vsc_str_buffer_t));

    self->refcnt = 1;

    vsc_str_buffer_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSC_PUBLIC void
vsc_str_buffer_cleanup(vsc_str_buffer_t *self) {

    if (self == NULL) {
        return;
    }

    vsc_str_buffer_cleanup_ctx(self);

    vsc_zeroize(self, sizeof(vsc_str_buffer_t));
}

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_new(void) {

    vsc_str_buffer_t *self = (vsc_str_buffer_t *) vsc_alloc(sizeof (vsc_str_buffer_t));
    VSC_ASSERT_ALLOC(self);

    vsc_str_buffer_init(self);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Allocate inner character buffer of given capacity.
//
VSC_PUBLIC void
vsc_str_buffer_init_with_capacity(vsc_str_buffer_t *self, size_t capacity) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vsc_str_buffer_t));

    self->refcnt = 1;

    vsc_str_buffer_init_ctx_with_capacity(self, capacity);
}

//
//  Allocate class context and perform it's initialization.
//  Allocate inner character buffer of given capacity.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_new_with_capacity(size_t capacity) {

    vsc_str_buffer_t *self = (vsc_str_buffer_t *) vsc_alloc(sizeof (vsc_str_buffer_t));
    VSC_ASSERT_ALLOC(self);

    vsc_str_buffer_init_with_capacity(self, capacity);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Allocate inner character buffer as copy of given string.
//
VSC_PUBLIC void
vsc_str_buffer_init_with_str(vsc_str_buffer_t *self, vsc_str_t str) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vsc_str_buffer_t));

    self->refcnt = 1;

    vsc_str_buffer_init_ctx_with_str(self, str);
}

//
//  Allocate class context and perform it's initialization.
//  Allocate inner character buffer as copy of given string.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_new_with_str(vsc_str_t str) {

    vsc_str_buffer_t *self = (vsc_str_buffer_t *) vsc_alloc(sizeof (vsc_str_buffer_t));
    VSC_ASSERT_ALLOC(self);

    vsc_str_buffer_init_with_str(self, str);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSC_PUBLIC void
vsc_str_buffer_delete(vsc_str_buffer_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vsc_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsc_str_buffer_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsc_str_buffer_new ()'.
//
VSC_PUBLIC void
vsc_str_buffer_destroy(vsc_str_buffer_t **self_ref) {

    VSC_ASSERT_PTR(self_ref);

    vsc_str_buffer_t *self = *self_ref;
    *self_ref = NULL;

    vsc_str_buffer_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSC_PUBLIC vsc_str_buffer_t *
vsc_str_buffer_shallow_copy(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    #if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsc_str_buffer_init() is called.
//  Note, that context is already zeroed.
//
static void
vsc_str_buffer_init_ctx(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_init(&self->buffer);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_str_buffer_cleanup_ctx(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_cleanup(&self->buffer);
}

//
//  Allocate inner character buffer of given capacity.
//
static void
vsc_str_buffer_init_ctx_with_capacity(vsc_str_buffer_t *self, size_t capacity) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_init_with_capacity(&self->buffer, capacity);
}

//
//  Allocate inner character buffer as copy of given string.
//
static void
vsc_str_buffer_init_ctx_with_str(vsc_str_buffer_t *self, vsc_str_t str) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_str_is_valid(str));

    vsc_buffer_init_with_data(&self->buffer, vsc_str_as_data(str));
}

//
//  Returns true if string length is zero.
//
VSC_PUBLIC bool
vsc_str_buffer_is_empty(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_buffer_is_empty(&self->buffer);
}

//
//  Return true if strings are equal.
//
VSC_PUBLIC bool
vsc_str_buffer_equal(const vsc_str_buffer_t *self, const vsc_str_buffer_t *rhs) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(rhs);

    return vsc_buffer_equal(&self->buffer, &rhs->buffer);
}

//
//  Perform constant-time string comparison.
//  The time depends on the string length but not on the characters.
//  Return true if strings are equal.
//
VSC_PUBLIC bool
vsc_str_buffer_secure_equal(const vsc_str_buffer_t *self, const vsc_str_buffer_t *rhs) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(rhs);

    return vsc_buffer_secure_equal(&self->buffer, &rhs->buffer);
}

//
//  Allocates inner characters array with a given capacity.
//  Precondition: characters array is initialized.
//  Precondition: characters array does not hold any character.
//  Postcondition: inner characters array is allocated.
//
VSC_PUBLIC void
vsc_str_buffer_alloc(vsc_str_buffer_t *self, size_t capacity) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_alloc(&self->buffer, capacity);
}

//
//  Release inner characters array.
//
VSC_PUBLIC void
vsc_str_buffer_release(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_release(&self->buffer);
}

//
//  Use given characters array as underlying string buffer.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any characters array.
//  Note, caller is responsible for given characters array deallocation.
//
VSC_PUBLIC void
vsc_str_buffer_use(vsc_str_buffer_t *self, char *chars, size_t chars_len) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(chars);

    vsc_buffer_use(&self->buffer, (byte *)chars, chars_len);
}

//
//  Take given characters array as underlying string buffer.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any characters array.
//  Note, this class is responsible for given characters array deallocation.
//
VSC_PUBLIC void
vsc_str_buffer_take(vsc_str_buffer_t *self, char *chars, size_t chars_len, vsc_dealloc_fn dealloc_cb) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(chars);

    vsc_buffer_take(&self->buffer, (byte *)chars, chars_len, dealloc_cb);
}

//
//  Mark string buffer as it holds sensitive data that must be erased
//  in a secure manner during destruction.
//
VSC_PUBLIC void
vsc_str_buffer_make_secure(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_make_secure(&self->buffer);
}

//
//  Returns true if string buffer is full.
//
VSC_PUBLIC bool
vsc_str_buffer_is_full(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_buffer_is_full(&self->buffer);
}

//
//  Returns true if string buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_str_buffer_is_valid(const vsc_str_buffer_t *self) {

    if (NULL == self) {
        return false;
    }

    return vsc_buffer_is_valid(&self->buffer);
}

//
//  Returns underlying characters array.
//
VSC_PUBLIC const char *
vsc_str_buffer_chars(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return (const char *)vsc_buffer_bytes(&self->buffer);
}

//
//  Returns underlying string buffer characters as string.
//
VSC_PUBLIC vsc_str_t
vsc_str_buffer_str(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_str_from_data(vsc_buffer_data(&self->buffer));
}

//
//  Returns underlying string buffer characters as data.
//
VSC_PUBLIC vsc_data_t
vsc_str_buffer_data(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_buffer_data(&self->buffer);
}

//
//  Returns string buffer capacity.
//
VSC_PUBLIC size_t
vsc_str_buffer_capacity(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_buffer_capacity(&self->buffer);
}

//
//  Returns string buffer effective length - length of characters that are actually used.
//
VSC_PUBLIC size_t
vsc_str_buffer_len(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_buffer_len(&self->buffer);
}

//
//  Returns length of the characters array that are not in use yet.
//
VSC_PUBLIC size_t
vsc_str_buffer_unused_len(const vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return vsc_buffer_unused_len(&self->buffer);
}

//
//  Returns writable pointer to the string buffer first element.
//
VSC_PUBLIC char *
vsc_str_buffer_begin(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return (char *)vsc_buffer_begin(&self->buffer);
}

//
//  Returns pointer to the first unused character in the string buffer.
//
VSC_PUBLIC char *
vsc_str_buffer_unused_chars(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return (char *)vsc_buffer_unused_bytes(&self->buffer);
}

//
//  Increase used characters by given length.
//
VSC_PUBLIC void
vsc_str_buffer_inc_used(vsc_str_buffer_t *self, size_t len) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_inc_used(&self->buffer, len);
}

//
//  Decrease used characters by given length.
//
VSC_PUBLIC void
vsc_str_buffer_dec_used(vsc_str_buffer_t *self, size_t len) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_dec_used(&self->buffer, len);
}

//
//  Copy string to the string buffer.
//
VSC_PUBLIC void
vsc_str_buffer_write_str(vsc_str_buffer_t *self, vsc_str_t str) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_write_data(&self->buffer, vsc_str_as_data(str));
}

//
//  Copy string to the string buffer and reallocate if needed by coping.
//
//  Precondition: string buffer should be an owner of the underlying characters array.
//
//  Note, this operation can be slow if copy operation occurred.
//  Note, string buffer capacity is doubled.
//
VSC_PUBLIC void
vsc_str_buffer_append_str(vsc_str_buffer_t *self, vsc_str_t str) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_append_data(&self->buffer, vsc_str_as_data(str));
}

//
//  Replace all occurences of one character to another character.
//
VSC_PUBLIC void
vsc_str_buffer_replace_char(vsc_str_buffer_t *self, char char_old, char char_new) {

    VSC_ASSERT(vsc_str_buffer_is_valid(self));

    char *str = vsc_str_buffer_begin(self);

    for (size_t pos = 0; pos < vsc_str_buffer_len(self); ++pos) {
        if (str[pos] == char_old) {
            str[pos] = char_new;
        }
    }
}

//
//  Remove all occurences of given character from the string end.
//
VSC_PUBLIC void
vsc_str_buffer_rtrim(vsc_str_buffer_t *self, char char_to_trim) {

    char *str = vsc_str_buffer_chars(self);

    for (size_t len = vsc_str_buffer_len(self); len != 0 && str[len - 1] == char_to_trim; --len) {
        vsc_str_buffer_dec_used(self, 1);
    }
}

//
//  Reset to the initial state.
//  After reset underlying characters array can be re-used.
//
VSC_PUBLIC void
vsc_str_buffer_reset(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_reset(&self->buffer);
}

//
//  Zeroing output buffer in secure manner.
//  And reset it to the initial state.
//
VSC_PUBLIC void
vsc_str_buffer_erase(vsc_str_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_erase(&self->buffer);
}
