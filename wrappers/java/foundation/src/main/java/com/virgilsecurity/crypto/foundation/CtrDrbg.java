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

package com.virgilsecurity.crypto.foundation;

/*
* Implementation of the RNG using deterministic random bit generators
* based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
* This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled.
*/
public class CtrDrbg implements AutoCloseable, Random {

    public long cCtx;

    /* Create underlying C context. */
    public CtrDrbg() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.ctrDrbg_new();
    }

    /* Wrap underlying C context. */
    CtrDrbg(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * The interval before reseed is performed by default.
    */
    public int getReseedInterval() {
        return 10000;
    }

    /*
    * The amount of entropy used per seed by default.
    */
    public int getEntropyLen() {
        return 48;
    }

    public void setEntropySource(EntropySource entropySource) throws FoundationException {
        FoundationJNI.INSTANCE.ctrDrbg_setEntropySource(this.cCtx, entropySource);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.ctrDrbg_setupDefaults(this.cCtx);
    }

    /*
    * Force entropy to be gathered at the beginning of every call to
    * the random() method.
    * Note, use this if your entropy source has sufficient throughput.
    */
    public void enablePredictionResistance() {
        FoundationJNI.INSTANCE.ctrDrbg_enablePredictionResistance(this.cCtx);
    }

    /*
    * Sets the reseed interval.
    * Default value is reseed interval.
    */
    public void setReseedInterval(int interval) {
        FoundationJNI.INSTANCE.ctrDrbg_setReseedInterval(this.cCtx, interval);
    }

    /*
    * Sets the amount of entropy grabbed on each seed or reseed.
    * The default value is entropy len.
    */
    public void setEntropyLen(int len) {
        FoundationJNI.INSTANCE.ctrDrbg_setEntropyLen(this.cCtx, len);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static CtrDrbg getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new CtrDrbg(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.ctrDrbg_close(this.cCtx);
    }

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public byte[] random(int dataLen) throws FoundationException {
        return FoundationJNI.INSTANCE.ctrDrbg_random(this.cCtx, dataLen);
    }

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public void reseed() throws FoundationException {
        FoundationJNI.INSTANCE.ctrDrbg_reseed(this.cCtx);
    }
}

