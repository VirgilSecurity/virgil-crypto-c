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

package com.virgilsecurity.crypto.phe;

import com.virgilsecurity.crypto.common.utils.NativeUtils;
import com.virgilsecurity.crypto.foundation.*;

public class PheJNI {

    public static final PheJNI INSTANCE;

    static {
        NativeUtils.load("vsce_phe");
        INSTANCE = new PheJNI();
    }

    private PheJNI() {
    }

    public native long pheServer_new();

    public native void pheServer_close(long cCtx);

    public native void pheServer_setRandom(long cCtx, Random random);

    public native void pheServer_setOperationRandom(long cCtx, Random operationRandom);

    public native long pheClient_new();

    public native void pheClient_close(long cCtx);

    public native void pheClient_setRandom(long cCtx, Random random);

    public native void pheClient_setOperationRandom(long cCtx, Random operationRandom);

    public native long pheCipher_new();

    public native void pheCipher_close(long cCtx);

    public native void pheCipher_setRandom(long cCtx, Random random);

    public native long uokmsClient_new();

    public native void uokmsClient_close(long cCtx);

    public native void uokmsClient_setRandom(long cCtx, Random random);

    public native void uokmsClient_setOperationRandom(long cCtx, Random operationRandom);

    public native long uokmsServer_new();

    public native void uokmsServer_close(long cCtx);

    public native void uokmsServer_setRandom(long cCtx, Random random);

    public native void uokmsServer_setOperationRandom(long cCtx, Random operationRandom);

    public native long uokmsWrapRotation_new();

    public native void uokmsWrapRotation_close(long cCtx);

    public native void uokmsWrapRotation_setOperationRandom(long cCtx, Random operationRandom);

}
