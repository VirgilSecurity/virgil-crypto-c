/*
* Copyright (C) 2015-2021 Virgil Security, Inc.
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
* Handle algorithm information about ECP.
*/
public class EccAlgInfo implements AutoCloseable, AlgInfo {

    public long cCtx;

    /* Create underlying C context. */
    public EccAlgInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.eccAlgInfo_new();
    }

    /* Wrap underlying C context. */
    EccAlgInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Create algorithm info with EC generic key identificator, EC domain group identificator.
    */
    public EccAlgInfo(AlgId algId, OidId keyId, OidId domainId) {
        super();
        this.cCtx = FoundationJNI.INSTANCE.eccAlgInfo_new(algId, keyId, domainId);
    }

    /*
    * Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}.
    */
    public OidId keyId() {
        return FoundationJNI.INSTANCE.eccAlgInfo_keyId(this.cCtx);
    }

    /*
    * Return EC domain group identificator.
    */
    public OidId domainId() {
        return FoundationJNI.INSTANCE.eccAlgInfo_domainId(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static EccAlgInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new EccAlgInfo(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.eccAlgInfo_close(ctx);
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
        return FoundationJNI.INSTANCE.eccAlgInfo_algId(this.cCtx);
    }
}

