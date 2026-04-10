//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Create algorithms based on the given information.
// --------------------------------------------------------------------------

#ifndef VSCF_ALG_FACTORY_H_INCLUDED
#define VSCF_ALG_FACTORY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_alg_id.h"
#include "vscf_impl.h"

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
//  Handle 'alg factory' context.
//
typedef struct vscf_alg_factory_t vscf_alg_factory_t;

//
//  Return size of 'vscf_alg_factory_t'.
//
VSCF_PUBLIC size_t
vscf_alg_factory_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_alg_factory_init(vscf_alg_factory_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_alg_factory_cleanup(vscf_alg_factory_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_alg_factory_t *
vscf_alg_factory_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_alg_factory_delete(vscf_alg_factory_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_alg_factory_new ()'.
//
VSCF_PUBLIC void
vscf_alg_factory_destroy(vscf_alg_factory_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_alg_factory_t *
vscf_alg_factory_shallow_copy(vscf_alg_factory_t *self);

//
//  Create algorithm that implements "hash stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_hash_from_alg_id(vscf_alg_id_t alg_id);

//
//  Create algorithm that implements "hash stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_hash_from_info(vscf_impl_t *alg_info);

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_mac_from_alg_id(vscf_alg_id_t alg_id);

//
//  Create algorithm that implements "mac stream" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_mac_from_info(vscf_impl_t *alg_info);

//
//  Create algorithm that implements "kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_kdf_from_alg_id(vscf_alg_id_t alg_id);

//
//  Create algorithm that implements "kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_kdf_from_info(vscf_impl_t *alg_info);

//
//  Create algorithm that implements "salted kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_salted_kdf_from_alg_id(vscf_alg_id_t alg_id);

//
//  Create algorithm that implements "salted kdf" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_salted_kdf_from_info(vscf_impl_t *alg_info);

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_cipher_from_alg_id(vscf_alg_id_t alg_id);

//
//  Create algorithm that implements "cipher" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_cipher_from_info(vscf_impl_t *alg_info);

//
//  Create algorithm that implements "padding" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_padding_from_alg_id(vscf_alg_id_t alg_id, vscf_impl_t *random);

//
//  Create algorithm that implements "padding" interface.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_create_padding_from_info(vscf_impl_t *alg_info, vscf_impl_t *random);

//
//  Restore algorithm info within a given algorithm and returns it if success,
//  or delete it and returns NULL;
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_factory_restore_alg_info_and_return(vscf_impl_t *alg, vscf_impl_t *alg_info);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ALG_FACTORY_H_INCLUDED
//  @end
