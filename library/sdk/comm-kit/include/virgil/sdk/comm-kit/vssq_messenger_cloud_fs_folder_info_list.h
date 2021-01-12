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
//  Handles a list of "messenger cloud fs folder info" class objects.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST_H_INCLUDED
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_cloud_fs_folder_info.h"

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
//  Handle 'messenger cloud fs folder info list' context.
//
#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST_T_DEFINED
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST_T_DEFINED
    typedef struct vssq_messenger_cloud_fs_folder_info_list_t vssq_messenger_cloud_fs_folder_info_list_t;
#endif // VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST_T_DEFINED

//
//  Return size of 'vssq_messenger_cloud_fs_folder_info_list_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_folder_info_list_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_init(vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_cleanup(vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_delete(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_folder_info_list_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_destroy(vssq_messenger_cloud_fs_folder_info_list_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_shallow_copy(vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_shallow_copy_const(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Add new item to the list.
//  Note, ownership is retained.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_add(vssq_messenger_cloud_fs_folder_info_list_t *self,
        vssq_messenger_cloud_fs_folder_info_t *folder_info);

//
//  Remove current node.
//
VSSQ_PRIVATE void
vssq_messenger_cloud_fs_folder_info_list_remove_self(vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return true if given list has item.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_info_list_has_item(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return list item.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_folder_info_list_item(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return true if list has next item.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_info_list_has_next(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return next list node if exists, or NULL otherwise.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_next(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return true if list has previous item.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_info_list_has_prev(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return previous list node if exists, or NULL otherwise.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_prev(const vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Remove all items.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_clear(vssq_messenger_cloud_fs_folder_info_list_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST_H_INCLUDED
//  @end
