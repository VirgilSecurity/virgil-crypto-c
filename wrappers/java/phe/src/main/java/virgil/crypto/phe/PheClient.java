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

package virgil.crypto.phe;

import virgil.crypto.foundation.*;

/*
* Class for client-side PHE crypto operations.
* This class is thread-safe in case if VSCE_MULTI_THREAD defined
*/
public class PheClient implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public PheClient() {
        super();
        this.cCtx = PheJNI.INSTANCE.pheClient_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public PheClient(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        PheJNI.INSTANCE.pheClient_close(this.cCtx);
    }

    /*
    * Random used for key generation, proofs, etc.
    */
    public void setRandom(Random random) {
        PheJNI.INSTANCE.pheClient_setRandom(this.cCtx, random);
    }

    /*
    * Random used for crypto operations to make them const-time
    */
    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.pheClient_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.pheClient_setupDefaults(this.cCtx);
    }

    /*
    * Sets client private and server public key
    * Call this method before any other methods except `update enrollment record` and `generate client private key`
    * This function should be called only once
    */
    public void setKeys(byte[] clientPrivateKey, byte[] serverPublicKey) throws PheException {
        PheJNI.INSTANCE.pheClient_setKeys(this.cCtx, clientPrivateKey, serverPublicKey);
    }

    /*
    * Generates client private key
    */
    public byte[] generateClientPrivateKey() throws PheException {
        return PheJNI.INSTANCE.pheClient_generateClientPrivateKey(this.cCtx);
    }

    /*
    * Buffer size needed to fit EnrollmentRecord
    */
    public int enrollmentRecordLen() {
        return PheJNI.INSTANCE.pheClient_enrollmentRecordLen(this.cCtx);
    }

    /*
    * Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
    * a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
    * Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
    */
    public PheClientEnrollAccountResult enrollAccount(byte[] enrollmentResponse, byte[] password) throws PheException {
        return PheJNI.INSTANCE.pheClient_enrollAccount(this.cCtx, enrollmentResponse, password);
    }

    /*
    * Buffer size needed to fit VerifyPasswordRequest
    */
    public int verifyPasswordRequestLen() {
        return PheJNI.INSTANCE.pheClient_verifyPasswordRequestLen(this.cCtx);
    }

    /*
    * Creates a request for further password verification at the PHE server side.
    */
    public byte[] createVerifyPasswordRequest(byte[] password, byte[] enrollmentRecord) throws PheException {
        return PheJNI.INSTANCE.pheClient_createVerifyPasswordRequest(this.cCtx, password, enrollmentRecord);
    }

    /*
    * Verifies PHE server's answer
    * If login succeeded, extracts account key
    * If login failed account key will be empty
    */
    public byte[] checkResponseAndDecrypt(byte[] password, byte[] enrollmentRecord, byte[] verifyPasswordResponse) throws PheException {
        return PheJNI.INSTANCE.pheClient_checkResponseAndDecrypt(this.cCtx, password, enrollmentRecord, verifyPasswordResponse);
    }

    /*
    * Updates client's private key and server's public key using server's update token
    * Use output values to instantiate new client instance with new keys
    */
    public PheClientRotateKeysResult rotateKeys(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.pheClient_rotateKeys(this.cCtx, updateToken);
    }

    /*
    * Updates EnrollmentRecord using server's update token
    */
    public byte[] updateEnrollmentRecord(byte[] enrollmentRecord, byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.pheClient_updateEnrollmentRecord(this.cCtx, enrollmentRecord, updateToken);
    }
}

