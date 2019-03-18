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

#ifndef PYTHIA_PYTHIA_WRAPPER_H
#define PYTHIA_PYTHIA_WRAPPER_H

#include "pythia_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Blinds password. Turns password into a pseudo-random string. This step is necessary to prevent 3rd-parties from knowledge of end user's password.
/// \param [in] password end user's password.
/// \param [out] G1 blinded_password password obfuscated into a pseudo-random string.
/// \param [out] BN blinding_secret random value used to blind user's password.
/// \return 0 if succeeded, -1 otherwise
int pythia_w_blind(const pythia_buf_t *password, pythia_buf_t *blinded_password, pythia_buf_t *blinding_secret);

/// Deblinds transformed_password value with previously returned blinding_secret from pythia_blind.
/// \param [in] GT transformed_password transformed password from pythia_transform.
/// \param [in] BN blinding_secret value that was generated in pythia_blind.
/// \param [out] GT deblinded_password deblinded transformed_password value. This value is not equal to password and is zero-knowledge protected.
/// \return 0 if succeeded, -1 otherwise
int pythia_w_deblind(const pythia_buf_t *transformed_password, const pythia_buf_t *blinding_secret,
                     pythia_buf_t *deblinded_password);

/// Computes transformation private and public key.
/// \param [in] transformation_key_id ensemble key ID used to enclose operations in subsets.
/// \param [in] pythia_secret global common for all secret random Key.
/// \param [in] pythia_scope_secret ensemble secret generated and versioned transparently.
/// \param [out] BN transformation_private_key Pythia's private key which was generated using pythia_secret and pythia_scope_secret. This key is used to emit proof tokens (proof_value_c, proof_value_u).
/// \param [out] G1 transformation_public_key public key corresponding to transformation_private_key value. This value is exposed to the client so he can verify transform operations
/// \return 0 if succeeded, -1 otherwise
int pythia_w_compute_transformation_key_pair(const pythia_buf_t *transformation_key_id,
                                             const pythia_buf_t *pythia_secret,
                                             const pythia_buf_t *pythia_scope_secret,
                                             pythia_buf_t *transformation_private_key,
                                             pythia_buf_t *transformation_public_key);

/// Transforms blinded password using transformation private key.
/// \param [in] G1 blinded_password password obfuscated into a pseudo-random string.
/// \param [in] tweak some random value used to identify user
/// \param [in] BN transformation_private_key transformation private key.
/// \param [out] GT transformed_password blinded password, protected using server secret (transformation private key + tweak).
/// \param [out] G2 transformed_tweak tweak value turned into an elliptic curve point. This value is used by Prove() operation.
/// \return 0 if succeeded, -1 otherwise
int pythia_w_transform(const pythia_buf_t *blinded_password, const pythia_buf_t *tweak,
                       const pythia_buf_t *transformation_private_key, pythia_buf_t *transformed_password,
                       pythia_buf_t *transformed_tweak);

/// Generates proof that server possesses secret values that were used to transform password.
/// \param [in] GT transformed_password transformed password from pythia_transform
/// \param [in] G1 blinded_password blinded password from pythia_blind.
/// \param [in] G2 transformed_tweak transformed tweak from pythia_transform.
/// \param [in] BN transformation_private_key transformation private key.
/// \param [in] G1 transformation_public_key public key corresponding to transformation_private_key.
/// \param [out] BN proof_value_c first part of proof that transformed+password was created using transformation_private_key.
/// \param [out] BN proof_value_u second part of proof that transformed+password was created using transformation_private_key.
/// \return 0 if succeeded, -1 otherwise
int pythia_w_prove(const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                   const pythia_buf_t *transformed_tweak, const pythia_buf_t *transformation_private_key,
                   const pythia_buf_t *transformation_public_key,
                   pythia_buf_t *proof_value_c, pythia_buf_t *proof_value_u);

/// This operation allows client to verify that the output of pythia_transform is correct, assuming that client has previously stored transformation public key.
/// \param [in] GT transformed_password transformed password from pythia_transform
/// \param [in] G1 blinded_password blinded password from pythia_blind.
/// \param [in] tweak tweak from pythia_transform
/// \param [in] G1 transformation_public_key transformation public key
/// \param [in] BN proof_value_c proof value C from pythia_prove
/// \param [in] BN proof_value_u proof value U from pythia_prove
/// \param [out] verified 0 if verification failed, not 0 - otherwise
/// \return 0 if succeeded, -1 otherwise
int pythia_w_verify(const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                    const pythia_buf_t *tweak, const pythia_buf_t *transformation_public_key,
                    const pythia_buf_t *proof_value_c, const pythia_buf_t *proof_value_u, int *verified);

/// Rotates old transformation key to new transformation key and generates password_update_token that can update deblinded_passwords. This action should increment version of the pythia_scope_secret.
/// \param [in] previous_transformation_private_key previous transformation private key
/// \param [in] new_transformation_private_key new transformation private key
/// \param [out] BN password_update_token value that allows to update all deblinded passwords (one by one) after server issued new pythia_secret or pythia_scope_secret.
/// \return 0 if succeeded, -1 otherwise
int pythia_w_get_password_update_token(const pythia_buf_t *previous_transformation_private_key,
                                       const pythia_buf_t *new_transformation_private_key,
                                       pythia_buf_t *password_update_token);

/// Updates previously stored deblinded_password with password_update_token. After this call, pythia_transform called with new arguments will return corresponding values.
/// \param [in] GT deblinded_password previous deblinded password from pythia_deblind.
/// \param [in] BN password_update_token password update token from pythia_get_password_update_token
/// \param [out] GT updated_deblinded_password new deblinded password.
/// \return 0 if succeeded, -1 otherwise
int pythia_w_update_deblinded_with_token(const pythia_buf_t *deblinded_password,
                                         const pythia_buf_t *password_update_token,
                                         pythia_buf_t *updated_deblinded_password);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_WRAPPER_H
