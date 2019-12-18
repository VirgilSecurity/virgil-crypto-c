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

package com.virgilsecurity.crypto.phe;

import com.virgilsecurity.crypto.foundation.*;

public class UokmsServer implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public UokmsServer() {
        super();
        this.cCtx = PheJNI.INSTANCE.uokmsServer_new();
    }

    /* Wrap underlying C context. */
    UokmsServer(PheContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static UokmsServer getInstance(long cCtx) {
        PheContextHolder ctxHolder = new PheContextHolder(cCtx);
        return new UokmsServer(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        PheJNI.INSTANCE.uokmsServer_close(this.cCtx);
    }

    /*
    * Random used for key generation, proofs, etc.
    */
    public void setRandom(Random random) {
        PheJNI.INSTANCE.uokmsServer_setRandom(this.cCtx, random);
    }

    /*
    * Random used for crypto operations to make them const-time
    */
    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.uokmsServer_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.uokmsServer_setupDefaults(this.cCtx);
    }

    /*
    * Generates new NIST P-256 server key pair for some client
    */
    public UokmsServerGenerateServerKeyPairResult generateServerKeyPair() throws PheException {
        return PheJNI.INSTANCE.uokmsServer_generateServerKeyPair(this.cCtx);
    }

    /*
    * Generates a new random enrollment and proof for a new user
    */
    public byte[] processDecryptRequest(byte[] serverPrivateKey, byte[] decryptRequest) throws PheException {
        return PheJNI.INSTANCE.uokmsServer_processDecryptRequest(this.cCtx, serverPrivateKey, decryptRequest);
    }

    /*
    * Updates server's private and public keys and issues an update token for use on client's side
    */
    public UokmsServerRotateKeysResult rotateKeys(byte[] serverPrivateKey) throws PheException {
        return PheJNI.INSTANCE.uokmsServer_rotateKeys(this.cCtx, serverPrivateKey);
    }

    /*
    * Updates EnrollmentRecord using server's update token
    */
    public byte[] updateWrap(byte[] wrap, byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.uokmsServer_updateWrap(this.cCtx, wrap, updateToken);
    }
}

