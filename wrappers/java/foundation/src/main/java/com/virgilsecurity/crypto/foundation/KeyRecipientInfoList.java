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
* Handles a list of "key recipient info" class objects.
*/
public class KeyRecipientInfoList implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public KeyRecipientInfoList() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyRecipientInfoList_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public KeyRecipientInfoList(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.keyRecipientInfoList_close(this.cCtx);
    }

    /*
    * Add new item to the list.
    * Note, ownership is transfered.
    */
    public void add(KeyRecipientInfo keyRecipientInfo) {
        FoundationJNI.INSTANCE.keyRecipientInfoList_add(this.cCtx, keyRecipientInfo);
    }

    /*
    * Return true if given list has item.
    */
    public boolean hasItem() {
        return FoundationJNI.INSTANCE.keyRecipientInfoList_hasItem(this.cCtx);
    }

    /*
    * Return list item.
    */
    public KeyRecipientInfo item() {
        return FoundationJNI.INSTANCE.keyRecipientInfoList_item(this.cCtx);
    }

    /*
    * Return true if list has next item.
    */
    public boolean hasNext() {
        return FoundationJNI.INSTANCE.keyRecipientInfoList_hasNext(this.cCtx);
    }

    /*
    * Return next list node if exists, or NULL otherwise.
    */
    public KeyRecipientInfoList next() {
        return FoundationJNI.INSTANCE.keyRecipientInfoList_next(this.cCtx);
    }

    /*
    * Return true if list has previous item.
    */
    public boolean hasPrev() {
        return FoundationJNI.INSTANCE.keyRecipientInfoList_hasPrev(this.cCtx);
    }

    /*
    * Return previous list node if exists, or NULL otherwise.
    */
    public KeyRecipientInfoList prev() {
        return FoundationJNI.INSTANCE.keyRecipientInfoList_prev(this.cCtx);
    }

    /*
    * Remove all items.
    */
    public void clear() {
        FoundationJNI.INSTANCE.keyRecipientInfoList_clear(this.cCtx);
    }
}

