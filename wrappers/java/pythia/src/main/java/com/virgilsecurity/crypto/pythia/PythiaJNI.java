/*
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

    public native void pythia_configure() throws PythiaException;

    public native void pythia_cleanup();

    public native int pythia_blindedPasswordBufLen();

    public native int pythia_deblindedPasswordBufLen();

    public native int pythia_blindingSecretBufLen();

    public native int pythia_transformationPrivateKeyBufLen();

    public native int pythia_transformationPublicKeyBufLen();

    public native int pythia_transformedPasswordBufLen();

    public native int pythia_transformedTweakBufLen();

    public native int pythia_proofValueBufLen();

    public native int pythia_passwordUpdateTokenBufLen();

    public native PythiaBlindResult pythia_blind(byte[] password) throws PythiaException;

    public native byte[] pythia_deblind(byte[] transformedPassword, byte[] blindingSecret) throws PythiaException;

    public native PythiaComputeTransformationKeyPairResult pythia_computeTransformationKeyPair(byte[] transformationKeyId, byte[] pythiaSecret, byte[] pythiaScopeSecret) throws PythiaException;

    public native PythiaTransformResult pythia_transform(byte[] blindedPassword, byte[] tweak, byte[] transformationPrivateKey) throws PythiaException;

    public native PythiaProveResult pythia_prove(byte[] transformedPassword, byte[] blindedPassword, byte[] transformedTweak, byte[] transformationPrivateKey, byte[] transformationPublicKey) throws PythiaException;

    public native boolean pythia_verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak, byte[] transformationPublicKey, byte[] proofValueC, byte[] proofValueU) throws PythiaException;

    public native byte[] pythia_getPasswordUpdateToken(byte[] previousTransformationPrivateKey, byte[] newTransformationPrivateKey) throws PythiaException;

    public native byte[] pythia_updateDeblindedWithToken(byte[] deblindedPassword, byte[] passwordUpdateToken) throws PythiaException;

}
