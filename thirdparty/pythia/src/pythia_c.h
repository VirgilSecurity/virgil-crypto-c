/**
 * Copyright (C) 2015-2018 Virgil Security Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PYTHIA_PYTHIA_C_H
#define PYTHIA_PYTHIA_C_H

#include <stdint.h>
#include <relic/relic.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Blinds password. Turns password into a pseudo-random string. This step is necessary to prevent 3rd-parties from knowledge of end user's password.
/// \param [in] m end user's password.
/// \param [in] m_size password size.
/// \param [out] x password obfuscated into a pseudo-random string.
/// \param [out] rInv random value used to blind user's password.
void pythia_blind(const uint8_t *m, size_t m_size, g1_t x, bn_t rInv);

/// Deblinds transformed_password value with previously returned blinding_secret from pythia_blind.
/// \param [in] y transformed password from pythia_transform.
/// \param [in] rInv value that was generated in pythia_blind.
/// \param [out] u deblinded transformed_password value. This value is not equal to password and is zero-knowledge protected.
void pythia_deblind(gt_t y, bn_t rInv, gt_t u);

/// Computes transformation private/public key pair
/// \param [in] w ensemble key ID used to enclose operations in subsets.
/// \param [in] w_size transformation_key_id size.
/// \param [in] msk global common for all secret random Key.
/// \param [in] msk_size pythia_secret size.
/// \param [in] s ensemble secret generated and versioned transparently.
/// \param [in] s_size pythia_scope_secret size
/// \param [out] kw transformation private key.
/// \param [out] pi_p transformation public key. This value is exposed to the client so he can verify eval operations.
void pythia_compute_kw(const uint8_t *w, size_t w_size, const uint8_t *msk, size_t msk_size,
                       const uint8_t *s, size_t s_size,
                       bn_t kw, g1_t pi_p);

/// Transforms blinded password using transformation private key.
/// \param [in] x password obfuscated into a pseudo-random string.
/// \param [in] t tweak, some random value used to identify user
/// \param [in] t_size tweak size
/// \param [out] kw Pythia's private key which was generated using pythia_secret and pythia_scope_secret.
/// \param [out] y blinded password, protected using server secret (transformation private key + tweak).
/// \param [out] tTilde tweak value turned into an elliptic curve point. This value is used by Prove() operation.
void pythia_eval(g1_t x, const uint8_t *t, size_t t_size, bn_t kw, gt_t y, g2_t tTilde);

/// Generates proof that server possesses secret values that were used to transform password.
/// \param [in] y transformed password from pythia_transform
/// \param [in] x blinded password from pythia_blind.
/// \param [in] tTilde transformed tweak from pythia_transform.
/// \param [in] kw transformation private key.
/// \param [in] pi_p public key corresponding to kw.
/// \param [out] pi_c first part of proof that transformed+password was created using transformation_private_key.
/// \param [out] pi_u second part of proof that transformed+password was created using transformation_private_key.
void pythia_prove(gt_t y, g1_t x, g2_t tTilde, bn_t kw, g1_t pi_p, bn_t pi_c, bn_t pi_u);

/// This operation allows client to verify that the output of pythia_transform is correct, assuming that client has previously stored transformation public key pi_p.
/// \param [in] y transformed password from pythia_transform
/// \param [in] x blinded password from pythia_blind.
/// \param [in] t tweak
/// \param [in] t_size tweak size
/// \param [in] pi_p transformation public key
/// \param [in] pi_c proof value C from pythia_prove
/// \param [in] pi_u proof value U from pythia_prove
/// \param [out] verified 0 if verification failed, not 0 - otherwise
void pythia_verify(gt_t y, g1_t x, const uint8_t *t, size_t t_size, g1_t pi_p, bn_t pi_c, bn_t pi_u, int *verified);

/// Rotates old transformation key to new transformation key and generates a password_update_token that can update deblinded passwords. This action should increment version of the pythia_scope_secret.
/// \param [in] kw0 previous transformation private key
/// \param [in] kw1 new transformation private key
/// \param [out] password_update_token value that allows to update all deblinded passwords (one by one) after server issued new pythia_secret or pythia_scope_secret.
void get_delta(bn_t kw0, bn_t kw1, bn_t password_update_token);

/// Updates previously stored deblinded_password with password_update_token.
/// \param [in] u0 previous deblinded password from pythia_deblind.
/// \param [in] delta password update token
/// \param [out] u1 new deblinded password.
void pythia_update_with_delta(gt_t u0, bn_t delta, gt_t u1);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_C_H
