/*
* Copyright (C) 2015-2020 Virgil Security, Inc.
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

import com.virgilsecurity.crypto.common.utils.NativeUtils;

public class PythiaJNI {

    public static final PythiaJNI INSTANCE;

    static {
        NativeUtils.load("vscp_pythia");
        INSTANCE = new PythiaJNI();
    }

    private PythiaJNI() {
    }

    /*
    * Performs global initialization of the pythia library.
    * Must be called once for entire application at startup.
    */
    public native void pythia_configure() throws PythiaException;

    /*
    * Performs global cleanup of the pythia library.
    * Must be called once for entire application before exit.
    */
    public native void pythia_cleanup();

    /*
    * Return length of the buffer needed to hold 'blinded password'.
    */
    public native int pythia_blindedPasswordBufLen();

    /*
    * Return length of the buffer needed to hold 'deblinded password'.
    */
    public native int pythia_deblindedPasswordBufLen();

    /*
    * Return length of the buffer needed to hold 'blinding secret'.
    */
    public native int pythia_blindingSecretBufLen();

    /*
    * Return length of the buffer needed to hold 'transformation private key'.
    */
    public native int pythia_transformationPrivateKeyBufLen();

    /*
    * Return length of the buffer needed to hold 'transformation public key'.
    */
    public native int pythia_transformationPublicKeyBufLen();

    /*
    * Return length of the buffer needed to hold 'transformed password'.
    */
    public native int pythia_transformedPasswordBufLen();

    /*
    * Return length of the buffer needed to hold 'transformed tweak'.
    */
    public native int pythia_transformedTweakBufLen();

    /*
    * Return length of the buffer needed to hold 'proof value'.
    */
    public native int pythia_proofValueBufLen();

    /*
    * Return length of the buffer needed to hold 'password update token'.
    */
    public native int pythia_passwordUpdateTokenBufLen();

    /*
    * Blinds password. Turns password into a pseudo-random string.
    * This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    */
    public native PythiaBlindResult pythia_blind(byte[] password) throws PythiaException;

    /*
    * Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
    */
    public native byte[] pythia_deblind(byte[] transformedPassword, byte[] blindingSecret) throws PythiaException;

    /*
    * Computes transformation private and public key.
    */
    public native PythiaComputeTransformationKeyPairResult pythia_computeTransformationKeyPair(byte[] transformationKeyId, byte[] pythiaSecret, byte[] pythiaScopeSecret) throws PythiaException;

    /*
    * Transforms blinded password using transformation private key.
    */
    public native PythiaTransformResult pythia_transform(byte[] blindedPassword, byte[] tweak, byte[] transformationPrivateKey) throws PythiaException;

    /*
    * Generates proof that server possesses secret values that were used to transform password.
    */
    public native PythiaProveResult pythia_prove(byte[] transformedPassword, byte[] blindedPassword, byte[] transformedTweak, byte[] transformationPrivateKey, byte[] transformationPublicKey) throws PythiaException;

    /*
    * This operation allows client to verify that the output of transform() is correct,
    * assuming that client has previously stored transformation public key.
    */
    public native boolean pythia_verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak, byte[] transformationPublicKey, byte[] proofValueC, byte[] proofValueU) throws PythiaException;

    /*
    * Rotates old transformation key to new transformation key and generates 'password update token',
    * that can update 'deblinded password'(s).
    *
    * This action should increment version of the 'pythia scope secret'.
    */
    public native byte[] pythia_getPasswordUpdateToken(byte[] previousTransformationPrivateKey, byte[] newTransformationPrivateKey) throws PythiaException;

    /*
    * Updates previously stored 'deblinded password' with 'password update token'.
    * After this call, 'transform()' called with new arguments will return corresponding values.
    */
    public native byte[] pythia_updateDeblindedWithToken(byte[] deblindedPassword, byte[] passwordUpdateToken) throws PythiaException;
}

