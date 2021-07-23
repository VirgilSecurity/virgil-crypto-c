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
* CMS based serialization of the class "message info".
*/
public class MessageInfoDerSerializer implements AutoCloseable, MessageInfoSerializer, MessageInfoFooterSerializer {

    public long cCtx;

    /* Create underlying C context. */
    public MessageInfoDerSerializer() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoDerSerializer_new();
    }

    /* Wrap underlying C context. */
    MessageInfoDerSerializer(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setAsn1Reader(Asn1Reader asn1Reader) {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_setAsn1Reader(this.cCtx, asn1Reader);
    }

    public void setAsn1Writer(Asn1Writer asn1Writer) {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_setAsn1Writer(this.cCtx, asn1Writer);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_setupDefaults(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static MessageInfoDerSerializer getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfoDerSerializer(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.messageInfoDerSerializer_close(ctx);
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

    public int getPrefixLen() {
        return 32;
    }

    /*
    * Return buffer size enough to hold serialized message info.
    */
    public int serializedLen(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedLen(this.cCtx, messageInfo);
    }

    /*
    * Serialize class "message info".
    */
    public byte[] serialize(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serialize(this.cCtx, messageInfo);
    }

    /*
    * Read message info prefix from the given data, and if it is valid,
    * return a length of bytes of the whole message info.
    *
    * Zero returned if length can not be determined from the given data,
    * and this means that there is no message info at the data beginning.
    */
    public int readPrefix(byte[] data) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_readPrefix(this.cCtx, data);
    }

    /*
    * Deserialize class "message info".
    */
    public MessageInfo deserialize(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_deserialize(this.cCtx, data);
    }

    /*
    * Return buffer size enough to hold serialized message info footer.
    */
    public int serializedFooterLen(MessageInfoFooter messageInfoFooter) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedFooterLen(this.cCtx, messageInfoFooter);
    }

    /*
    * Serialize class "message info footer".
    */
    public byte[] serializeFooter(MessageInfoFooter messageInfoFooter) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeFooter(this.cCtx, messageInfoFooter);
    }

    /*
    * Deserialize class "message info footer".
    */
    public MessageInfoFooter deserializeFooter(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeFooter(this.cCtx, data);
    }
}

