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
* Handle information about an encrypted message and algorithms
* that was used for encryption.
*/
public class MessageInfo implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public MessageInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfo_new();
    }

    /* Wrap underlying C context. */
    MessageInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static MessageInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfo(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.messageInfo_close(this.cCtx);
    }

    /*
    * Return information about algorithm that was used for the data encryption.
    */
    public AlgInfo dataEncryptionAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_dataEncryptionAlgInfo(this.cCtx);
    }

    /*
    * Return list with a "key recipient info" elements.
    */
    public KeyRecipientInfoList keyRecipientInfoList() {
        return FoundationJNI.INSTANCE.messageInfo_keyRecipientInfoList(this.cCtx);
    }

    /*
    * Return list with a "password recipient info" elements.
    */
    public PasswordRecipientInfoList passwordRecipientInfoList() {
        return FoundationJNI.INSTANCE.messageInfo_passwordRecipientInfoList(this.cCtx);
    }

    /*
    * Return true if message info contains at least one custom param.
    */
    public boolean hasCustomParams() {
        return FoundationJNI.INSTANCE.messageInfo_hasCustomParams(this.cCtx);
    }

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    * If custom params object was not set then new empty object is created.
    */
    public MessageInfoCustomParams customParams() {
        return FoundationJNI.INSTANCE.messageInfo_customParams(this.cCtx);
    }

    /*
    * Return true if cipher kdf alg info exists.
    */
    public boolean hasCipherKdfAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_hasCipherKdfAlgInfo(this.cCtx);
    }

    /*
    * Return cipher kdf alg info.
    */
    public AlgInfo cipherKdfAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_cipherKdfAlgInfo(this.cCtx);
    }

    /*
    * Return true if cipher padding alg info exists.
    */
    public boolean hasCipherPaddingAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_hasCipherPaddingAlgInfo(this.cCtx);
    }

    /*
    * Return cipher padding alg info.
    */
    public AlgInfo cipherPaddingAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_cipherPaddingAlgInfo(this.cCtx);
    }

    /*
    * Return true if footer info exists.
    */
    public boolean hasFooterInfo() {
        return FoundationJNI.INSTANCE.messageInfo_hasFooterInfo(this.cCtx);
    }

    /*
    * Return footer info.
    */
    public FooterInfo footerInfo() {
        return FoundationJNI.INSTANCE.messageInfo_footerInfo(this.cCtx);
    }

    /*
    * Remove all infos.
    */
    public void clear() {
        FoundationJNI.INSTANCE.messageInfo_clear(this.cCtx);
    }
}

