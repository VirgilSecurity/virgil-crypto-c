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

package com.virgilsecurity.crypto.foundation;

/*
* Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm.
*/
public class Pkcs5Pbkdf2 implements AutoCloseable, Alg, Kdf, SaltedKdf {

    public long cCtx;

    /* Create underlying C context. */
    public Pkcs5Pbkdf2() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.pkcs5Pbkdf2_new();
    }

    /* Wrap underlying C context. */
    Pkcs5Pbkdf2(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setHmac(Mac hmac) {
        FoundationJNI.INSTANCE.pkcs5Pbkdf2_setHmac(this.cCtx, hmac);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() {
        FoundationJNI.INSTANCE.pkcs5Pbkdf2_setupDefaults(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Pkcs5Pbkdf2 getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Pkcs5Pbkdf2(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.pkcs5Pbkdf2_close(ctx);
        }
    }

    /* Close resource. */
    public void close() {
        clearResources();
    }

    /* Finalize resource. */
    protected void finalize() throws Throwable {
        clearResources();
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.pkcs5Pbkdf2_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.pkcs5Pbkdf2_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.pkcs5Pbkdf2_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Derive key of the requested length from the given data.
    */
    public byte[] derive(byte[] data, int keyLen) {
        return FoundationJNI.INSTANCE.pkcs5Pbkdf2_derive(this.cCtx, data, keyLen);
    }

    /*
    * Prepare algorithm to derive new key.
    */
    public void reset(byte[] salt, int iterationCount) {
        FoundationJNI.INSTANCE.pkcs5Pbkdf2_reset(this.cCtx, salt, iterationCount);
    }

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    public void setInfo(byte[] info) {
        FoundationJNI.INSTANCE.pkcs5Pbkdf2_setInfo(this.cCtx, info);
    }
}

