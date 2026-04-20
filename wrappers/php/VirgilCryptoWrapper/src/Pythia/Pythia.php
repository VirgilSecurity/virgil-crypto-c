<?php
/**
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

namespace Virgil\CryptoWrapper\Pythia;

class Pythia
{

    /**
    *
    * @return void
    * @throws \Exception
    */
    public static function configure(): void
    {
        vscp_pythia_configure_php();
    }

    /**
    *
    * @return void
    */
    public static function cleanup(): void
    {
        vscp_pythia_cleanup_php();
    }

    /**
    *
    * @return int
    */
    public static function blindedPasswordBufLen(): int
    {
        return vscp_pythia_blinded_password_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function deblindedPasswordBufLen(): int
    {
        return vscp_pythia_deblinded_password_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function blindingSecretBufLen(): int
    {
        return vscp_pythia_blinding_secret_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function transformationPrivateKeyBufLen(): int
    {
        return vscp_pythia_transformation_private_key_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function transformationPublicKeyBufLen(): int
    {
        return vscp_pythia_transformation_public_key_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function transformedPasswordBufLen(): int
    {
        return vscp_pythia_transformed_password_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function transformedTweakBufLen(): int
    {
        return vscp_pythia_transformed_tweak_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function proofValueBufLen(): int
    {
        return vscp_pythia_proof_value_buf_len_php();
    }

    /**
    *
    * @return int
    */
    public static function passwordUpdateTokenBufLen(): int
    {
        return vscp_pythia_password_update_token_buf_len_php();
    }

    /**
    *
    * @param string $$password
    * @return array
    * @throws \Exception
    */
    public static function blind(string $$password)
    {
        return vscp_pythia_blind_php($$password);
    }

    /**
    *
    * @param string $$transformedPassword
    * @param string $$blindingSecret
    * @return string
    * @throws \Exception
    */
    public static function deblind(string $$transformedPassword, string $$blindingSecret): string
    {
        return vscp_pythia_deblind_php($$transformedPassword, $$blindingSecret);
    }

    /**
    *
    * @param string $$transformationKeyId
    * @param string $$pythiaSecret
    * @param string $$pythiaScopeSecret
    * @return array
    * @throws \Exception
    */
    public static function computeTransformationKeyPair(string $$transformationKeyId, string $$pythiaSecret, string $$pythiaScopeSecret)
    {
        return vscp_pythia_compute_transformation_key_pair_php($$transformationKeyId, $$pythiaSecret, $$pythiaScopeSecret);
    }

    /**
    *
    * @param string $$blindedPassword
    * @param string $$tweak
    * @param string $$transformationPrivateKey
    * @return array
    * @throws \Exception
    */
    public static function transform(string $$blindedPassword, string $$tweak, string $$transformationPrivateKey)
    {
        return vscp_pythia_transform_php($$blindedPassword, $$tweak, $$transformationPrivateKey);
    }

    /**
    *
    * @param string $$transformedPassword
    * @param string $$blindedPassword
    * @param string $$transformedTweak
    * @param string $$transformationPrivateKey
    * @param string $$transformationPublicKey
    * @return array
    * @throws \Exception
    */
    public static function prove(string $$transformedPassword, string $$blindedPassword, string $$transformedTweak, string $$transformationPrivateKey, string $$transformationPublicKey)
    {
        return vscp_pythia_prove_php($$transformedPassword, $$blindedPassword, $$transformedTweak, $$transformationPrivateKey, $$transformationPublicKey);
    }

    /**
    *
    * @param string $$transformedPassword
    * @param string $$blindedPassword
    * @param string $$tweak
    * @param string $$transformationPublicKey
    * @param string $$proofValueC
    * @param string $$proofValueU
    * @return bool
    * @throws \Exception
    */
    public static function verify(string $$transformedPassword, string $$blindedPassword, string $$tweak, string $$transformationPublicKey, string $$proofValueC, string $$proofValueU): bool
    {
        return vscp_pythia_verify_php($$transformedPassword, $$blindedPassword, $$tweak, $$transformationPublicKey, $$proofValueC, $$proofValueU);
    }

    /**
    *
    * @param string $$previousTransformationPrivateKey
    * @param string $$newTransformationPrivateKey
    * @return string
    * @throws \Exception
    */
    public static function getPasswordUpdateToken(string $$previousTransformationPrivateKey, string $$newTransformationPrivateKey): string
    {
        return vscp_pythia_get_password_update_token_php($$previousTransformationPrivateKey, $$newTransformationPrivateKey);
    }

    /**
    *
    * @param string $$deblindedPassword
    * @param string $$passwordUpdateToken
    * @return string
    * @throws \Exception
    */
    public static function updateDeblindedWithToken(string $$deblindedPassword, string $$passwordUpdateToken): string
    {
        return vscp_pythia_update_deblinded_with_token_php($$deblindedPassword, $$passwordUpdateToken);
    }

}
