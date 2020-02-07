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
* Random number generator that generate deterministic sequence based
* on a given seed.
* This RNG can be used to transform key material rial to the private key.
*/
public class KeyMaterialRng implements AutoCloseable, Random {

    public long cCtx;

    /* Create underlying C context. */
    public KeyMaterialRng() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyMaterialRng_new();
    }

    /* Wrap underlying C context. */
    KeyMaterialRng(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Minimum length in bytes for the key material.
    */
    public int getKeyMaterialLenMin() {
        return 32;
    }

    /*
    * Maximum length in bytes for the key material.
    */
    public int getKeyMaterialLenMax() {
        return 512;
    }

    /*
    * Set a new key material.
    */
    public void resetKeyMaterial(byte[] keyMaterial) {
        FoundationJNI.INSTANCE.keyMaterialRng_resetKeyMaterial(this.cCtx, keyMaterial);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static KeyMaterialRng getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new KeyMaterialRng(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.keyMaterialRng_close(ctx);
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
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public byte[] random(int dataLen) throws FoundationException {
        return FoundationJNI.INSTANCE.keyMaterialRng_random(this.cCtx, dataLen);
    }

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public void reseed() throws FoundationException {
        FoundationJNI.INSTANCE.keyMaterialRng_reseed(this.cCtx);
    }
}

