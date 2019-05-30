/*
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

package com.virgilsecurity.crypto.pythia;

/*
* Provide Pythia implementation based on the Virgil Security.
*/
public class Pythia {

    /*
    * Performs global initialization of the pythia library.
    * Must be called once for entire application at startup.
    */
    public static void configure() throws PythiaException {
        PythiaJNI.INSTANCE.pythia_configure();
    }

    /*
    * Performs global cleanup of the pythia library.
    * Must be called once for entire application before exit.
    */
    public static void cleanup() {
        PythiaJNI.INSTANCE.pythia_cleanup();
    }

    /*
    * Return length of the buffer needed to hold 'blinded password'.
    */
    public static int blindedPasswordBufLen() {
        return PythiaJNI.INSTANCE.pythia_blindedPasswordBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'deblinded password'.
    */
    public static int deblindedPasswordBufLen() {
        return PythiaJNI.INSTANCE.pythia_deblindedPasswordBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'blinding secret'.
    */
    public static int blindingSecretBufLen() {
        return PythiaJNI.INSTANCE.pythia_blindingSecretBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'transformation private key'.
    */
    public static int transformationPrivateKeyBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformationPrivateKeyBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'transformation public key'.
    */
    public static int transformationPublicKeyBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformationPublicKeyBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'transformed password'.
    */
    public static int transformedPasswordBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformedPasswordBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'transformed tweak'.
    */
    public static int transformedTweakBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformedTweakBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'proof value'.
    */
    public static int proofValueBufLen() {
        return PythiaJNI.INSTANCE.pythia_proofValueBufLen();
    }

    /*
    * Return length of the buffer needed to hold 'password update token'.
    */
    public static int passwordUpdateTokenBufLen() {
        return PythiaJNI.INSTANCE.pythia_passwordUpdateTokenBufLen();
    }

    /*
    * Blinds password. Turns password into a pseudo-random string.
    * This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    */
    public static PythiaBlindResult blind(byte[] password) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_blind(password);
    }

    /*
    * Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
    */
    public static byte[] deblind(byte[] transformedPassword, byte[] blindingSecret) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_deblind(transformedPassword, blindingSecret);
    }

    /*
    * Computes transformation private and public key.
    */
    public static PythiaComputeTransformationKeyPairResult computeTransformationKeyPair(byte[] transformationKeyId, byte[] pythiaSecret, byte[] pythiaScopeSecret) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_computeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
    }

    /*
    * Transforms blinded password using transformation private key.
    */
    public static PythiaTransformResult transform(byte[] blindedPassword, byte[] tweak, byte[] transformationPrivateKey) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_transform(blindedPassword, tweak, transformationPrivateKey);
    }

    /*
    * Generates proof that server possesses secret values that were used to transform password.
    */
    public static PythiaProveResult prove(byte[] transformedPassword, byte[] blindedPassword, byte[] transformedTweak, byte[] transformationPrivateKey, byte[] transformationPublicKey) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_prove(transformedPassword, blindedPassword, transformedTweak, transformationPrivateKey, transformationPublicKey);
    }

    /*
    * This operation allows client to verify that the output of transform() is correct,
    * assuming that client has previously stored transformation public key.
    */
    public static boolean verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak, byte[] transformationPublicKey, byte[] proofValueC, byte[] proofValueU) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_verify(transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU);
    }

    /*
    * Rotates old transformation key to new transformation key and generates 'password update token',
    * that can update 'deblinded password'(s).
    *
    * This action should increment version of the 'pythia scope secret'.
    */
    public static byte[] getPasswordUpdateToken(byte[] previousTransformationPrivateKey, byte[] newTransformationPrivateKey) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_getPasswordUpdateToken(previousTransformationPrivateKey, newTransformationPrivateKey);
    }

    /*
    * Updates previously stored 'deblinded password' with 'password update token'.
    * After this call, 'transform()' called with new arguments will return corresponding values.
    */
    public static byte[] updateDeblindedWithToken(byte[] deblindedPassword, byte[] passwordUpdateToken) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_updateDeblindedWithToken(deblindedPassword, passwordUpdateToken);
    }
}

