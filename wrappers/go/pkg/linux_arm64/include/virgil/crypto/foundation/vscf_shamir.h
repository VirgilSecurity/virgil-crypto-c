//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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

#ifndef VSCF_SHAMIR_H_INCLUDED
#define VSCF_SHAMIR_H_INCLUDED

// clang-format on
//  @end

//  @generated_header_includes
// --------------------------------------------------------------------------
// clang-format off
//  Generated header includes start.
// --------------------------------------------------------------------------

#include "vscf_library.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_status.h"

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
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
//  Handle 'shamir' context.
//
typedef struct vscf_shamir_t vscf_shamir_t;

//
//  Return size of 'vscf_shamir_t'.
//
VSCF_PUBLIC size_t
vscf_shamir_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_shamir_init(vscf_shamir_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_shamir_cleanup(vscf_shamir_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_shamir_t *
vscf_shamir_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_shamir_delete(vscf_shamir_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_shamir_new ()'.
//
VSCF_PUBLIC void
vscf_shamir_destroy(vscf_shamir_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_shamir_t *
vscf_shamir_shallow_copy(vscf_shamir_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_shamir_use_random(vscf_shamir_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_shamir_take_random(vscf_shamir_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_shamir_release_random(vscf_shamir_t *self);

//
//  Setup predefined values to the uninitialized class dependencies:
//  a CTR DRBG random number generator.
//
VSCF_PUBLIC vscf_status_t
vscf_shamir_setup_defaults(vscf_shamir_t *self) VSCF_NODISCARD;

//
//  Calculate an upper bound on the length in bytes of a single share
//  produced for a secret of the given length. The buffer given to 'split'
//  must be at least this size; the actual written length may be a few
//  bytes smaller.
//
VSCF_PUBLIC size_t
vscf_shamir_share_len(const vscf_shamir_t *self, size_t secret_len);

//
//  Calculate an upper bound on the length in bytes of the buffer needed to
//  hold all shares produced by 'split' for a secret of the given length and
//  the given number of shares. The actual written length is reported on the
//  output buffer by 'split'.
//
VSCF_PUBLIC size_t
vscf_shamir_shares_len(const vscf_shamir_t *self, size_t secret_len, size_t share_count);

//
//  Calculate an upper bound on the length in bytes of the recovered secret
//  for the given total shares length and number of provided shares.
//  The exact length is set on the output buffer by 'combine'.
//
VSCF_PUBLIC size_t
vscf_shamir_recovered_secret_len(const vscf_shamir_t *self, size_t shares_len, size_t share_count);

//
//  Split the given secret into 'share count' shares with reconstruction
//  'threshold'. Requires a configured random number generator (see
//  'setup defaults' / 'use random').
//
//  Constraints: 1 <= threshold <= share count <= 255.
//
//  The produced shares are written consecutively to 'out', all of equal
//  length and each at most 'share len(secret.len)' bytes.
//
VSCF_PUBLIC vscf_status_t
vscf_shamir_split(vscf_shamir_t *self, vsc_data_t secret, size_t threshold, size_t share_count, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Reconstruct the secret from 'share count' shares concatenated in
//  'shares'. 'share count' must be at least the threshold used at split
//  time.
//
//  Returns 'success' and writes the secret to 'secret' on success.
//  Returns 'error bad arguments' if the shares are structurally invalid
//  (malformed/short input, inconsistent or duplicated shares, or shares
//  that do not belong to the same split). Returns 'error shamir recovery
//  failed' if the shares are structurally valid but cryptographically
//  wrong, tampered, or insufficient to meet the threshold. On any failure
//  the output buffer is left empty.
//
VSCF_PUBLIC vscf_status_t
vscf_shamir_combine(const vscf_shamir_t *self, vsc_data_t shares, size_t share_count, vsc_buffer_t *secret) VSCF_NODISCARD;

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end

#ifdef __cplusplus
}
#endif

//  @footer
#endif // VSCF_SHAMIR_H_INCLUDED
//  @end
