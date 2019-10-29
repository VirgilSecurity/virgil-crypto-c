<?php
/**
* Copyright (C) 2015-2019 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

namespace VirgilCrypto\Pythia;

/**
* Provide Pythia implementation based on the Virgil Security.
*/
class Pythia
{

    /**
    * Performs global initialization of the pythia library.
    * Must be called once for entire application at startup.
    *
    * @return void
    * @throws \Exception
    */
    public static function configure(): void
    {
        vscp_pythia_configure_php();
    }

    /**
    * Performs global cleanup of the pythia library.
    * Must be called once for entire application before exit.
    *
    * @return void
    */
    public static function cleanup(): void
    {
        vscp_pythia_cleanup_php();
    }

    /**
    * Return length of the buffer needed to hold 'blinded password'.
    *
    * @return int
    */
    public static function blindedPasswordBufLen(): int
    {
        return vscp_pythia_blinded_password_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'deblinded password'.
    *
    * @return int
    */
    public static function deblindedPasswordBufLen(): int
    {
        return vscp_pythia_deblinded_password_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'blinding secret'.
    *
    * @return int
    */
    public static function blindingSecretBufLen(): int
    {
        return vscp_pythia_blinding_secret_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'transformation private key'.
    *
    * @return int
    */
    public static function transformationPrivateKeyBufLen(): int
    {
        return vscp_pythia_transformation_private_key_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'transformation public key'.
    *
    * @return int
    */
    public static function transformationPublicKeyBufLen(): int
    {
        return vscp_pythia_transformation_public_key_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'transformed password'.
    *
    * @return int
    */
    public static function transformedPasswordBufLen(): int
    {
        return vscp_pythia_transformed_password_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'transformed tweak'.
    *
    * @return int
    */
    public static function transformedTweakBufLen(): int
    {
        return vscp_pythia_transformed_tweak_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'proof value'.
    *
    * @return int
    */
    public static function proofValueBufLen(): int
    {
        return vscp_pythia_proof_value_buf_len_php();
    }

    /**
    * Return length of the buffer needed to hold 'password update token'.
    *
    * @return int
    */
    public static function passwordUpdateTokenBufLen(): int
    {
        return vscp_pythia_password_update_token_buf_len_php();
    }

    /**
    * Blinds password. Turns password into a pseudo-random string.
    * This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    *
    * @param string $password
    * @return array
    * @throws \Exception
    */
    public static function blind(string $password): array // [blinded_password, blinding_secret]
    {
        return vscp_pythia_blind_php($password);
    }

    /**
    * Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
    *
    * @param string $transformedPassword
    * @param string $blindingSecret
    * @return string
    * @throws \Exception
    */
    public static function deblind(string $transformedPassword, string $blindingSecret): string
    {
        return vscp_pythia_deblind_php($transformedPassword, $blindingSecret);
    }

    /**
    * Computes transformation private and public key.
    *
    * @param string $transformationKeyId
    * @param string $pythiaSecret
    * @param string $pythiaScopeSecret
    * @return array
    * @throws \Exception
    */
    public static function computeTransformationKeyPair(string $transformationKeyId, string $pythiaSecret, string $pythiaScopeSecret): array // [transformation_private_key, transformation_public_key]
    {
        return vscp_pythia_compute_transformation_key_pair_php($transformationKeyId, $pythiaSecret, $pythiaScopeSecret);
    }

    /**
    * Transforms blinded password using transformation private key.
    *
    * @param string $blindedPassword
    * @param string $tweak
    * @param string $transformationPrivateKey
    * @return array
    * @throws \Exception
    */
    public static function transform(string $blindedPassword, string $tweak, string $transformationPrivateKey): array // [transformed_password, transformed_tweak]
    {
        return vscp_pythia_transform_php($blindedPassword, $tweak, $transformationPrivateKey);
    }

    /**
    * Generates proof that server possesses secret values that were used to transform password.
    *
    * @param string $transformedPassword
    * @param string $blindedPassword
    * @param string $transformedTweak
    * @param string $transformationPrivateKey
    * @param string $transformationPublicKey
    * @return array
    * @throws \Exception
    */
    public static function prove(string $transformedPassword, string $blindedPassword, string $transformedTweak, string $transformationPrivateKey, string $transformationPublicKey): array // [proof_value_c, proof_value_u]
    {
        return vscp_pythia_prove_php($transformedPassword, $blindedPassword, $transformedTweak, $transformationPrivateKey, $transformationPublicKey);
    }

    /**
    * This operation allows client to verify that the output of transform() is correct,
    * assuming that client has previously stored transformation public key.
    *
    * @param string $transformedPassword
    * @param string $blindedPassword
    * @param string $tweak
    * @param string $transformationPublicKey
    * @param string $proofValueC
    * @param string $proofValueU
    * @return bool
    */
    public static function verify(string $transformedPassword, string $blindedPassword, string $tweak, string $transformationPublicKey, string $proofValueC, string $proofValueU): bool
    {
        return vscp_pythia_verify_php($transformedPassword, $blindedPassword, $tweak, $transformationPublicKey, $proofValueC, $proofValueU);
    }

    /**
    * Rotates old transformation key to new transformation key and generates 'password update token',
    * that can update 'deblinded password'(s).
    *
    * This action should increment version of the 'pythia scope secret'.
    *
    * @param string $previousTransformationPrivateKey
    * @param string $newTransformationPrivateKey
    * @return string
    * @throws \Exception
    */
    public static function getPasswordUpdateToken(string $previousTransformationPrivateKey, string $newTransformationPrivateKey): string
    {
        return vscp_pythia_get_password_update_token_php($previousTransformationPrivateKey, $newTransformationPrivateKey);
    }

    /**
    * Updates previously stored 'deblinded password' with 'password update token'.
    * After this call, 'transform()' called with new arguments will return corresponding values.
    *
    * @param string $deblindedPassword
    * @param string $passwordUpdateToken
    * @return string
    * @throws \Exception
    */
    public static function updateDeblindedWithToken(string $deblindedPassword, string $passwordUpdateToken): string
    {
        return vscp_pythia_update_deblinded_with_token_php($deblindedPassword, $passwordUpdateToken);
    }
}
