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
* Handle information about password-based encryption algorithm.
*/
public class PbeAlgInfo implements AutoCloseable, AlgInfo {

    public long cCtx;

    /* Create underlying C context. */
    public PbeAlgInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.pbeAlgInfo_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public PbeAlgInfo(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Create algorithm info with identificator, KDF algorithm info and
    * cipher alg info.
    */
    public PbeAlgInfo(AlgId algId, AlgInfo kdfAlgInfo, AlgInfo cipherAlgInfo) {
        super();
        this.cCtx = FoundationJNI.INSTANCE.pbeAlgInfo_new(algId, kdfAlgInfo, cipherAlgInfo);
    }

    /*
    * Return KDF algorithm information.
    */
    public AlgInfo kdfAlgInfo() {
        return FoundationJNI.INSTANCE.pbeAlgInfo_kdfAlgInfo(this.cCtx);
    }

    /*
    * Return cipher algorithm information.
    */
    public AlgInfo cipherAlgInfo() {
        return FoundationJNI.INSTANCE.pbeAlgInfo_cipherAlgInfo(this.cCtx);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.pbeAlgInfo_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.pbeAlgInfo_algId(this.cCtx);
    }
}
