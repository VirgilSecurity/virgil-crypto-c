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

package com.virgilsecurity.crypto.phe;

import com.virgilsecurity.crypto.common.utils.NativeUtils;

import com.virgilsecurity.crypto.foundation.*;

public class PheJNI {

    public static final PheJNI INSTANCE;

    static {
        NativeUtils.load("vsce_phe");
        INSTANCE = new PheJNI();
    }

    private PheJNI() {
    }

    public native long pheServer_new();

    public native void pheServer_close(long cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void pheServer_setRandom(long cCtx, Random random) throws PheException;

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void pheServer_setOperationRandom(long cCtx, Random operationRandom) throws PheException;

    /*
    * Setups dependencies with default values.
    */
    public native void pheServer_setupDefaults(long cCtx) throws PheException;

    /*
    * Generates new NIST P-256 server key pair for some client
    */
    public native PheServerGenerateServerKeyPairResult pheServer_generateServerKeyPair(long cCtx) throws PheException;

    /*
    * Buffer size needed to fit EnrollmentResponse
    */
    public native int pheServer_enrollmentResponseLen(long cCtx);

    /*
    * Generates a new random enrollment and proof for a new user
    */
    public native byte[] pheServer_getEnrollment(long cCtx, byte[] serverPrivateKey, byte[] serverPublicKey) throws PheException;

    /*
    * Buffer size needed to fit VerifyPasswordResponse
    */
    public native int pheServer_verifyPasswordResponseLen(long cCtx);

    /*
    * Verifies existing user's password and generates response with proof
    */
    public native byte[] pheServer_verifyPassword(long cCtx, byte[] serverPrivateKey, byte[] serverPublicKey, byte[] verifyPasswordRequest) throws PheException;

    /*
    * Buffer size needed to fit UpdateToken
    */
    public native int pheServer_updateTokenLen(long cCtx);

    /*
    * Updates server's private and public keys and issues an update token for use on client's side
    */
    public native PheServerRotateKeysResult pheServer_rotateKeys(long cCtx, byte[] serverPrivateKey) throws PheException;

    public native long pheClient_new();

    public native void pheClient_close(long cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void pheClient_setRandom(long cCtx, Random random) throws PheException;

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void pheClient_setOperationRandom(long cCtx, Random operationRandom) throws PheException;

    /*
    * Setups dependencies with default values.
    */
    public native void pheClient_setupDefaults(long cCtx) throws PheException;

    /*
    * Sets client private and server public key
    * Call this method before any other methods except `update enrollment record` and `generate client private key`
    * This function should be called only once
    */
    public native void pheClient_setKeys(long cCtx, byte[] clientPrivateKey, byte[] serverPublicKey) throws PheException;

    /*
    * Generates client private key
    */
    public native byte[] pheClient_generateClientPrivateKey(long cCtx) throws PheException;

    /*
    * Buffer size needed to fit EnrollmentRecord
    */
    public native int pheClient_enrollmentRecordLen(long cCtx);

    /*
    * Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
    * a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
    * Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
    */
    public native PheClientEnrollAccountResult pheClient_enrollAccount(long cCtx, byte[] enrollmentResponse, byte[] password) throws PheException;

    /*
    * Buffer size needed to fit VerifyPasswordRequest
    */
    public native int pheClient_verifyPasswordRequestLen(long cCtx);

    /*
    * Creates a request for further password verification at the PHE server side.
    */
    public native byte[] pheClient_createVerifyPasswordRequest(long cCtx, byte[] password, byte[] enrollmentRecord) throws PheException;

    /*
    * Verifies PHE server's answer
    * If login succeeded, extracts account key
    * If login failed account key will be empty
    */
    public native byte[] pheClient_checkResponseAndDecrypt(long cCtx, byte[] password, byte[] enrollmentRecord, byte[] verifyPasswordResponse) throws PheException;

    /*
    * Updates client's private key and server's public key using server's update token
    * Use output values to instantiate new client instance with new keys
    */
    public native PheClientRotateKeysResult pheClient_rotateKeys(long cCtx, byte[] updateToken) throws PheException;

    /*
    * Updates EnrollmentRecord using server's update token
    */
    public native byte[] pheClient_updateEnrollmentRecord(long cCtx, byte[] enrollmentRecord, byte[] updateToken) throws PheException;

    public native long pheCipher_new();

    public native void pheCipher_close(long cCtx);

    /*
    * Random used for salt generation
    */
    public native void pheCipher_setRandom(long cCtx, Random random);

    /*
    * Setups dependencies with default values.
    */
    public native void pheCipher_setupDefaults(long cCtx) throws PheException;

    /*
    * Returns buffer capacity needed to fit cipher text
    */
    public native int pheCipher_encryptLen(long cCtx, int plainTextLen);

    /*
    * Returns buffer capacity needed to fit plain text
    */
    public native int pheCipher_decryptLen(long cCtx, int cipherTextLen);

    /*
    * Encrypts data using account key
    */
    public native byte[] pheCipher_encrypt(long cCtx, byte[] plainText, byte[] accountKey) throws PheException;

    /*
    * Decrypts data using account key
    */
    public native byte[] pheCipher_decrypt(long cCtx, byte[] cipherText, byte[] accountKey) throws PheException;

    /*
    * Encrypts data (and authenticates additional data) using account key
    */
    public native byte[] pheCipher_authEncrypt(long cCtx, byte[] plainText, byte[] additionalData, byte[] accountKey) throws PheException;

    /*
    * Decrypts data (and verifies additional data) using account key
    */
    public native byte[] pheCipher_authDecrypt(long cCtx, byte[] cipherText, byte[] additionalData, byte[] accountKey) throws PheException;

    public native long uokmsClient_new();

    public native void uokmsClient_close(long cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void uokmsClient_setRandom(long cCtx, Random random) throws PheException;

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void uokmsClient_setOperationRandom(long cCtx, Random operationRandom) throws PheException;

    /*
    * Setups dependencies with default values.
    */
    public native void uokmsClient_setupDefaults(long cCtx) throws PheException;

    /*
    * Sets client private
    * Call this method before any other methods
    * This function should be called only once
    */
    public native void uokmsClient_setKeysOneparty(long cCtx, byte[] clientPrivateKey) throws PheException;

    /*
    * Sets client private and server public key
    * Call this method before any other methods
    * This function should be called only once
    */
    public native void uokmsClient_setKeys(long cCtx, byte[] clientPrivateKey, byte[] serverPublicKey) throws PheException;

    /*
    * Generates client private key
    */
    public native byte[] uokmsClient_generateClientPrivateKey(long cCtx) throws PheException;

    /*
    * Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
    * of "encryption key len" that can be used for symmetric encryption
    */
    public native UokmsClientGenerateEncryptWrapResult uokmsClient_generateEncryptWrap(long cCtx, int encryptionKeyLen) throws PheException;

    /*
    * Decrypt
    */
    public native byte[] uokmsClient_decryptOneparty(long cCtx, byte[] wrap, int encryptionKeyLen) throws PheException;

    /*
    * Generates request to decrypt data, this request should be sent to the server.
    * Server response is then passed to "process decrypt response" where encryption key can be decapsulated
    */
    public native UokmsClientGenerateDecryptRequestResult uokmsClient_generateDecryptRequest(long cCtx, byte[] wrap) throws PheException;

    /*
    * Processed server response, checks server proof and decapsulates encryption key
    */
    public native byte[] uokmsClient_processDecryptResponse(long cCtx, byte[] wrap, byte[] decryptRequest, byte[] decryptResponse, byte[] deblindFactor, int encryptionKeyLen) throws PheException;

    /*
    * Rotates client key using given update token obtained from server
    */
    public native byte[] uokmsClient_rotateKeysOneparty(long cCtx, byte[] updateToken) throws PheException;

    /*
    * Generates update token for one-party mode
    */
    public native byte[] uokmsClient_generateUpdateTokenOneparty(long cCtx) throws PheException;

    /*
    * Rotates client and server keys using given update token obtained from server
    */
    public native UokmsClientRotateKeysResult uokmsClient_rotateKeys(long cCtx, byte[] updateToken) throws PheException;

    public native long uokmsServer_new();

    public native void uokmsServer_close(long cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void uokmsServer_setRandom(long cCtx, Random random) throws PheException;

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void uokmsServer_setOperationRandom(long cCtx, Random operationRandom) throws PheException;

    /*
    * Setups dependencies with default values.
    */
    public native void uokmsServer_setupDefaults(long cCtx) throws PheException;

    /*
    * Generates new NIST P-256 server key pair for some client
    */
    public native UokmsServerGenerateServerKeyPairResult uokmsServer_generateServerKeyPair(long cCtx) throws PheException;

    /*
    * Buffer size needed to fit DecryptResponse
    */
    public native int uokmsServer_decryptResponseLen(long cCtx);

    /*
    * Processed client's decrypt request
    */
    public native byte[] uokmsServer_processDecryptRequest(long cCtx, byte[] serverPrivateKey, byte[] decryptRequest) throws PheException;

    /*
    * Updates server's private and public keys and issues an update token for use on client's side
    */
    public native UokmsServerRotateKeysResult uokmsServer_rotateKeys(long cCtx, byte[] serverPrivateKey) throws PheException;

    public native long uokmsWrapRotation_new();

    public native void uokmsWrapRotation_close(long cCtx);

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void uokmsWrapRotation_setOperationRandom(long cCtx, Random operationRandom);

    /*
    * Setups dependencies with default values.
    */
    public native void uokmsWrapRotation_setupDefaults(long cCtx) throws PheException;

    /*
    * Sets update token. Should be called only once and before any other function
    */
    public native void uokmsWrapRotation_setUpdateToken(long cCtx, byte[] updateToken) throws PheException;

    /*
    * Updates EnrollmentRecord using server's update token
    */
    public native byte[] uokmsWrapRotation_updateWrap(long cCtx, byte[] wrap) throws PheException;
}

