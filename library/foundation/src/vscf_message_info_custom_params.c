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

#include "vscf_message_info_custom_params.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_message_info_custom_params_defs.h"
#include "vscf_list_key_value_node_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vscf_message_info_custom_params_OF_INT_TYPE = 1,
    vscf_message_info_custom_params_OF_STRING_TYPE = 2,
    vscf_message_info_custom_params_OF_DATA_TYPE = 3
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_info_custom_params_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_info_custom_params_init_ctx(vscf_message_info_custom_params_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_info_custom_params_cleanup_ctx(vscf_message_info_custom_params_t *self);

//
//  Add given node to the list ending.
//
static void
vscf_message_info_custom_params_add_node(vscf_message_info_custom_params_t *self,
        vscf_list_key_value_node_t **node_ref);

//
//  Add given node to the list ending.
//
static const vscf_list_key_value_node_t *
vscf_message_info_custom_params_find_node(vscf_message_info_custom_params_t *self, vsc_data_t key, int value_tag,
        vscf_error_ctx_t *error);

//
//  Return size of 'vscf_message_info_custom_params_t'.
//
VSCF_PUBLIC size_t
vscf_message_info_custom_params_ctx_size(void) {

    return sizeof(vscf_message_info_custom_params_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_init(vscf_message_info_custom_params_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_message_info_custom_params_t));

    self->refcnt = 1;

    vscf_message_info_custom_params_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_cleanup(vscf_message_info_custom_params_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_message_info_custom_params_cleanup_ctx(self);

        vscf_zeroize(self, sizeof(vscf_message_info_custom_params_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_message_info_custom_params_new(void) {

    vscf_message_info_custom_params_t *self = (vscf_message_info_custom_params_t *) vscf_alloc(sizeof (vscf_message_info_custom_params_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_message_info_custom_params_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_delete(vscf_message_info_custom_params_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_message_info_custom_params_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_info_custom_params_new ()'.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_destroy(vscf_message_info_custom_params_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_message_info_custom_params_t *self = *self_ref;
    *self_ref = NULL;

    vscf_message_info_custom_params_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_custom_params_t *
vscf_message_info_custom_params_shallow_copy(vscf_message_info_custom_params_t *self) {

    VSCF_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_info_custom_params_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_info_custom_params_init_ctx(vscf_message_info_custom_params_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_info_custom_params_cleanup_ctx(vscf_message_info_custom_params_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_list_key_value_node_t *next = self->key_value_node;

    while (next != NULL) {
        vscf_list_key_value_node_t *curr = next;
        next = next->next;
        vsc_buffer_destroy(&curr->key);

        switch (curr->value_tag) {
        case vscf_message_info_custom_params_OF_INT_TYPE:
            vscf_dealloc(curr->value);
            break;
        case vscf_message_info_custom_params_OF_STRING_TYPE:
        case vscf_message_info_custom_params_OF_DATA_TYPE:
            vsc_buffer_delete((vsc_buffer_t *)curr->value);
            break;
        default:
            VSCF_ASSERT(0 && "Unhandled node type.");
            break;
        }

        curr->value = NULL;
        vscf_dealloc(curr);
    }
}

//
//  Add custom parameter with integer value.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_int(vscf_message_info_custom_params_t *self, vsc_data_t key, int value) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);

    vscf_list_key_value_node_t *node = (vscf_list_key_value_node_t *)vscf_alloc(sizeof(vscf_list_key_value_node_t));
    node->key = vsc_buffer_new_with_data(key);
    node->value_tag = vscf_message_info_custom_params_OF_INT_TYPE;
    node->value = vscf_alloc(sizeof(int));
    VSCF_ASSERT_ALLOC(node->value);
    *(int *)(node->value) = value;

    vscf_message_info_custom_params_add_node(self, &node);
}

//
//  Add custom parameter with UTF8 string value.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_string(vscf_message_info_custom_params_t *self, vsc_data_t key, vsc_data_t value) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);
    VSCF_ASSERT(vsc_data_is_valid(value));
    VSCF_ASSERT(value.len > 0);

    vscf_list_key_value_node_t *node = (vscf_list_key_value_node_t *)vscf_alloc(sizeof(vscf_list_key_value_node_t));
    node->key = vsc_buffer_new_with_data(key);
    node->value_tag = vscf_message_info_custom_params_OF_STRING_TYPE;
    node->value = vsc_buffer_new_with_data(value);

    vscf_message_info_custom_params_add_node(self, &node);
}

//
//  Add custom parameter with octet string value.
//
VSCF_PUBLIC void
vscf_message_info_custom_params_add_data(vscf_message_info_custom_params_t *self, vsc_data_t key, vsc_data_t value) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);
    VSCF_ASSERT(vsc_data_is_valid(value));
    VSCF_ASSERT(value.len > 0);

    vscf_list_key_value_node_t *node = (vscf_list_key_value_node_t *)vscf_alloc(sizeof(vscf_list_key_value_node_t));
    node->key = vsc_buffer_new_with_data(key);
    node->value_tag = vscf_message_info_custom_params_OF_DATA_TYPE;
    node->value = vsc_buffer_new_with_data(value);

    vscf_message_info_custom_params_add_node(self, &node);
}

//
//  Return custom parameter with integer value.
//
VSCF_PUBLIC int
vscf_message_info_custom_params_find_int(
        vscf_message_info_custom_params_t *self, vsc_data_t key, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);

    const vscf_list_key_value_node_t *node =
            vscf_message_info_custom_params_find_node(self, key, vscf_message_info_custom_params_OF_INT_TYPE, error);

    if (node != NULL) {
        const int *value = (int *)node->value;
        return *value;
    }

    return 0;
}

//
//  Return custom parameter with UTF8 string value.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_custom_params_find_string(
        vscf_message_info_custom_params_t *self, vsc_data_t key, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);

    const vscf_list_key_value_node_t *node =
            vscf_message_info_custom_params_find_node(self, key, vscf_message_info_custom_params_OF_STRING_TYPE, error);

    if (node != NULL) {
        const vsc_buffer_t *value = (const vsc_buffer_t *)node->value;
        return vsc_buffer_data(value);
    }

    return vsc_data_empty();
}

//
//  Return custom parameter with octet string value.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_custom_params_find_data(
        vscf_message_info_custom_params_t *self, vsc_data_t key, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);

    const vscf_list_key_value_node_t *node =
            vscf_message_info_custom_params_find_node(self, key, vscf_message_info_custom_params_OF_DATA_TYPE, error);

    if (node != NULL) {
        const vsc_buffer_t *value = (const vsc_buffer_t *)node->value;
        return vsc_buffer_data(value);
    }

    return vsc_data_empty();
}

//
//  Add given node to the list ending.
//
static void
vscf_message_info_custom_params_add_node(
        vscf_message_info_custom_params_t *self, vscf_list_key_value_node_t **node_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(node_ref);
    VSCF_ASSERT_PTR(*node_ref);
    VSCF_ASSERT_NULL((*node_ref)->next);
    VSCF_ASSERT_NULL((*node_ref)->prev);

    if (NULL == self->key_value_node) {
        self->key_value_node = *node_ref;

    } else {
        vscf_list_key_value_node_t *last = self->key_value_node;
        while (last != NULL && last->next != NULL) {
            last = last->next;
        }

        VSCF_ASSERT_NULL(last->next);
        last->next = *node_ref;
        (*node_ref)->prev = last;
    }

    *node_ref = NULL;
}

//
//  Add given node to the list ending.
//
static const vscf_list_key_value_node_t *
vscf_message_info_custom_params_find_node(
        vscf_message_info_custom_params_t *self, vsc_data_t key, int value_tag, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(key.len > 0);

    for (const vscf_list_key_value_node_t *curr = self->key_value_node; curr != NULL; curr = curr->next) {
        VSCF_ASSERT_PTR(curr->key);
        if (vsc_data_equal(key, vsc_buffer_data(curr->key))) {
            if (curr->value_tag == value_tag) {
                return curr;
            } else {
                VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_error_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH);
                return NULL;
            }
        }
    }

    VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_error_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND);
    return NULL;
}

//
//  Return first param, or NULL if does not exist.
//
VSCF_PRIVATE const vscf_list_key_value_node_t *
vscf_message_info_custom_params_first_param(const vscf_message_info_custom_params_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->key_value_node;
}

//
//  Return next param, or NULL if does not exist.
//
VSCF_PRIVATE const vscf_list_key_value_node_t *
vscf_message_info_custom_params_next_param(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);

    return param->next;
}

//
//  Return parameter's key.
//
VSCF_PRIVATE vsc_data_t
vscf_message_info_custom_params_param_key(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);
    VSCF_ASSERT_PTR(param->key);

    return vsc_buffer_data(param->key);
}

//
//  Return true if given parameter holds an integer value.
//
VSCF_PRIVATE bool
vscf_message_info_custom_params_is_int_param(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);

    return param->value_tag == vscf_message_info_custom_params_OF_INT_TYPE;
}

//
//  Return parameter as an integer value.
//
VSCF_PRIVATE int
vscf_message_info_custom_params_as_int_value(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);
    VSCF_ASSERT_PTR(param->value);
    VSCF_ASSERT(vscf_message_info_custom_params_is_int_param(param));

    return *(int *)param->value;
}

//
//  Return true if given parameter holds a string value.
//
VSCF_PRIVATE bool
vscf_message_info_custom_params_is_string_param(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);

    return param->value_tag == vscf_message_info_custom_params_OF_STRING_TYPE;
}

//
//  Return parameter as a string value.
//
VSCF_PRIVATE vsc_data_t
vscf_message_info_custom_params_as_string_value(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);
    VSCF_ASSERT_PTR(param->value);
    VSCF_ASSERT(vscf_message_info_custom_params_is_string_param(param));

    return vsc_buffer_data((const vsc_buffer_t *)param->value);
}

//
//  Return true if given parameter holds a data value.
//
VSCF_PRIVATE bool
vscf_message_info_custom_params_is_data_param(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);

    return param->value_tag == vscf_message_info_custom_params_OF_DATA_TYPE;
}

//
//  Return parameter as a data value.
//
VSCF_PRIVATE vsc_data_t
vscf_message_info_custom_params_as_data_value(const vscf_list_key_value_node_t *param) {

    VSCF_ASSERT_PTR(param);
    VSCF_ASSERT_PTR(param->value);
    VSCF_ASSERT(vscf_message_info_custom_params_is_data_param(param));

    return vsc_buffer_data((const vsc_buffer_t *)param->value);
}
