/*
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

package com.virgilsecurity.crypto.pythia;

public class Pythia {

    public static void configure() throws PythiaException {
        PythiaJNI.INSTANCE.pythia_configure();
    }

    public static void cleanup() {
        PythiaJNI.INSTANCE.pythia_cleanup();
    }

    public static int blindedPasswordBufLen() {
        return PythiaJNI.INSTANCE.pythia_blindedPasswordBufLen();
    }

    public static int deblindedPasswordBufLen() {
        return PythiaJNI.INSTANCE.pythia_deblindedPasswordBufLen();
    }

    public static int blindingSecretBufLen() {
        return PythiaJNI.INSTANCE.pythia_blindingSecretBufLen();
    }

    public static int transformationPrivateKeyBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformationPrivateKeyBufLen();
    }

    public static int transformationPublicKeyBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformationPublicKeyBufLen();
    }

    public static int transformedPasswordBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformedPasswordBufLen();
    }

    public static int transformedTweakBufLen() {
        return PythiaJNI.INSTANCE.pythia_transformedTweakBufLen();
    }

    public static int proofValueBufLen() {
        return PythiaJNI.INSTANCE.pythia_proofValueBufLen();
    }

    public static int passwordUpdateTokenBufLen() {
        return PythiaJNI.INSTANCE.pythia_passwordUpdateTokenBufLen();
    }

    public static PythiaBlindResult blind(byte[] password) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_blind(password);
    }

    public static byte[] deblind(byte[] transformedPassword, byte[] blindingSecret) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_deblind(transformedPassword, blindingSecret);
    }

    public static PythiaComputeTransformationKeyPairResult computeTransformationKeyPair(byte[] transformationKeyId, byte[] pythiaSecret, byte[] pythiaScopeSecret) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_computeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
    }

    public static PythiaTransformResult transform(byte[] blindedPassword, byte[] tweak, byte[] transformationPrivateKey) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_transform(blindedPassword, tweak, transformationPrivateKey);
    }

    public static PythiaProveResult prove(byte[] transformedPassword, byte[] blindedPassword, byte[] transformedTweak, byte[] transformationPrivateKey, byte[] transformationPublicKey) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_prove(transformedPassword, blindedPassword, transformedTweak, transformationPrivateKey, transformationPublicKey);
    }

    public static boolean verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak, byte[] transformationPublicKey, byte[] proofValueC, byte[] proofValueU) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_verify(transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU);
    }

    public static byte[] getPasswordUpdateToken(byte[] previousTransformationPrivateKey, byte[] newTransformationPrivateKey) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_getPasswordUpdateToken(previousTransformationPrivateKey, newTransformationPrivateKey);
    }

    public static byte[] updateDeblindedWithToken(byte[] deblindedPassword, byte[] passwordUpdateToken) throws PythiaException {
        return PythiaJNI.INSTANCE.pythia_updateDeblindedWithToken(deblindedPassword, passwordUpdateToken);
    }

}
