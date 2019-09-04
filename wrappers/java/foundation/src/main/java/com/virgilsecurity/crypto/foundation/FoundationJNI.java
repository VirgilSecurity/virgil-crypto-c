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

import com.virgilsecurity.crypto.common.utils.NativeUtils;

public class FoundationJNI {

    public static final FoundationJNI INSTANCE;

    static {
        NativeUtils.load("vscf_foundation_d");
        INSTANCE = new FoundationJNI();
    }

    private FoundationJNI() {
    }

    /*
    * Return OID for given algorithm identifier.
    */
    public native byte[] oid_fromAlgId(AlgId algId);

    /*
    * Return algorithm identifier for given OID.
    */
    public native AlgId oid_toAlgId(byte[] oid);

    /*
    * Return OID for a given identifier.
    */
    public native byte[] oid_fromId(OidId oidId);

    /*
    * Return identifier for a given OID.
    */
    public native OidId oid_toId(byte[] oid);

    /*
    * Map oid identifier to the algorithm identifier.
    */
    public native AlgId oid_idToAlgId(OidId oidId);

    /*
    * Return true if given OIDs are equal.
    */
    public native boolean oid_equal(byte[] lhs, byte[] rhs);

    /*
    * Calculate length in bytes required to hold an encoded base64 string.
    */
    public native int base64_encodedLen(int dataLen);

    /*
    * Encode given data to the base64 format.
    * Note, written buffer is NOT null-terminated.
    */
    public native byte[] base64_encode(byte[] data);

    /*
    * Calculate length in bytes required to hold a decoded base64 string.
    */
    public native int base64_decodedLen(int strLen);

    /*
    * Decode given data from the base64 format.
    */
    public native byte[] base64_decode(byte[] str) throws FoundationException;

    /*
    * Return length in bytes required to hold wrapped PEM format.
    */
    public native int pem_wrappedLen(String title, int dataLen);

    /*
    * Takes binary data and wraps it to the simple PEM format - no
    * additional information just header-base64-footer.
    * Note, written buffer is NOT null-terminated.
    */
    public native byte[] pem_wrap(String title, byte[] data);

    /*
    * Return length in bytes required to hold unwrapped binary.
    */
    public native int pem_unwrappedLen(int pemLen);

    /*
    * Takes PEM data and extract binary data from it.
    */
    public native byte[] pem_unwrap(byte[] pem) throws FoundationException;

    /*
    * Returns PEM title if PEM data is valid, otherwise - empty data.
    */
    public native byte[] pem_title(byte[] pem);

    public native java.nio.ByteBuffer messageInfo_new();

    public native void messageInfo_close(java.nio.ByteBuffer cCtx);

    /*
    * Add recipient that is defined by Public Key.
    */
    public native void messageInfo_addKeyRecipient(java.nio.ByteBuffer cCtx, KeyRecipientInfo keyRecipient);

    /*
    * Add recipient that is defined by password.
    */
    public native void messageInfo_addPasswordRecipient(java.nio.ByteBuffer cCtx, PasswordRecipientInfo passwordRecipient);

    /*
    * Set information about algorithm that was used for data encryption.
    */
    public native void messageInfo_setDataEncryptionAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo dataEncryptionAlgInfo);

    /*
    * Return information about algorithm that was used for the data encryption.
    */
    public native AlgInfo messageInfo_dataEncryptionAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Return list with a "key recipient info" elements.
    */
    public native KeyRecipientInfoList messageInfo_keyRecipientInfoList(java.nio.ByteBuffer cCtx);

    /*
    * Return list with a "password recipient info" elements.
    */
    public native PasswordRecipientInfoList messageInfo_passwordRecipientInfoList(java.nio.ByteBuffer cCtx);

    /*
    * Setup custom params.
    */
    public native void messageInfo_setCustomParams(java.nio.ByteBuffer cCtx, MessageInfoCustomParams customParams);

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    * If custom params object was not set then new empty object is created.
    */
    public native MessageInfoCustomParams messageInfo_customParams(java.nio.ByteBuffer cCtx);

    /*
    * Remove all recipients.
    */
    public native void messageInfo_clearRecipients(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer keyRecipientInfo_new();

    public native void keyRecipientInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer keyRecipientInfo_new(byte[] recipientId, AlgInfo keyEncryptionAlgorithm, byte[] encryptedKey);

    /*
    * Return recipient identifier.
    */
    public native byte[] keyRecipientInfo_recipientId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that was used for encryption
    * a data encryption key.
    */
    public native AlgInfo keyRecipientInfo_keyEncryptionAlgorithm(java.nio.ByteBuffer cCtx);

    /*
    * Return an encrypted data encryption key.
    */
    public native byte[] keyRecipientInfo_encryptedKey(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer keyRecipientInfoList_new();

    public native void keyRecipientInfoList_close(java.nio.ByteBuffer cCtx);

    /*
    * Add new item to the list.
    * Note, ownership is transfered.
    */
    public native void keyRecipientInfoList_add(java.nio.ByteBuffer cCtx, KeyRecipientInfo keyRecipientInfo);

    /*
    * Return true if given list has item.
    */
    public native boolean keyRecipientInfoList_hasItem(java.nio.ByteBuffer cCtx);

    /*
    * Return list item.
    */
    public native KeyRecipientInfo keyRecipientInfoList_item(java.nio.ByteBuffer cCtx);

    /*
    * Return true if list has next item.
    */
    public native boolean keyRecipientInfoList_hasNext(java.nio.ByteBuffer cCtx);

    /*
    * Return next list node if exists, or NULL otherwise.
    */
    public native KeyRecipientInfoList keyRecipientInfoList_next(java.nio.ByteBuffer cCtx);

    /*
    * Return true if list has previous item.
    */
    public native boolean keyRecipientInfoList_hasPrev(java.nio.ByteBuffer cCtx);

    /*
    * Return previous list node if exists, or NULL otherwise.
    */
    public native KeyRecipientInfoList keyRecipientInfoList_prev(java.nio.ByteBuffer cCtx);

    /*
    * Remove all items.
    */
    public native void keyRecipientInfoList_clear(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer passwordRecipientInfo_new();

    public native void passwordRecipientInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer passwordRecipientInfo_new(AlgInfo keyEncryptionAlgorithm, byte[] encryptedKey);

    /*
    * Return algorithm information that was used for encryption
    * a data encryption key.
    */
    public native AlgInfo passwordRecipientInfo_keyEncryptionAlgorithm(java.nio.ByteBuffer cCtx);

    /*
    * Return an encrypted data encryption key.
    */
    public native byte[] passwordRecipientInfo_encryptedKey(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer passwordRecipientInfoList_new();

    public native void passwordRecipientInfoList_close(java.nio.ByteBuffer cCtx);

    /*
    * Add new item to the list.
    * Note, ownership is transfered.
    */
    public native void passwordRecipientInfoList_add(java.nio.ByteBuffer cCtx, PasswordRecipientInfo passwordRecipientInfo);

    /*
    * Return true if given list has item.
    */
    public native boolean passwordRecipientInfoList_hasItem(java.nio.ByteBuffer cCtx);

    /*
    * Return list item.
    */
    public native PasswordRecipientInfo passwordRecipientInfoList_item(java.nio.ByteBuffer cCtx);

    /*
    * Return true if list has next item.
    */
    public native boolean passwordRecipientInfoList_hasNext(java.nio.ByteBuffer cCtx);

    /*
    * Return next list node if exists, or NULL otherwise.
    */
    public native PasswordRecipientInfoList passwordRecipientInfoList_next(java.nio.ByteBuffer cCtx);

    /*
    * Return true if list has previous item.
    */
    public native boolean passwordRecipientInfoList_hasPrev(java.nio.ByteBuffer cCtx);

    /*
    * Return previous list node if exists, or NULL otherwise.
    */
    public native PasswordRecipientInfoList passwordRecipientInfoList_prev(java.nio.ByteBuffer cCtx);

    /*
    * Remove all items.
    */
    public native void passwordRecipientInfoList_clear(java.nio.ByteBuffer cCtx);

    /*
    * Create algorithm that implements "hash stream" interface.
    */
    public native Hash algFactory_createHashFromInfo(AlgInfo algInfo);

    /*
    * Create algorithm that implements "mac stream" interface.
    */
    public native Mac algFactory_createMacFromInfo(AlgInfo algInfo);

    /*
    * Create algorithm that implements "kdf" interface.
    */
    public native Kdf algFactory_createKdfFromInfo(AlgInfo algInfo);

    /*
    * Create algorithm that implements "salted kdf" interface.
    */
    public native SaltedKdf algFactory_createSaltedKdfFromInfo(AlgInfo algInfo);

    /*
    * Create algorithm that implements "cipher" interface.
    */
    public native Cipher algFactory_createCipherFromInfo(AlgInfo algInfo);

    /*
    * Create a key algorithm based on an identifier.
    */
    public native KeyAlg keyAlgFactory_createFromAlgId(AlgId algId, Random random) throws FoundationException;

    /*
    * Create a key algorithm correspond to a specific key.
    */
    public native KeyAlg keyAlgFactory_createFromKey(Key key, Random random) throws FoundationException;

    /*
    * Create a key algorithm that can import "raw public key".
    */
    public native KeyAlg keyAlgFactory_createFromRawPublicKey(RawPublicKey publicKey, Random random) throws FoundationException;

    /*
    * Create a key algorithm that can import "raw private key".
    */
    public native KeyAlg keyAlgFactory_createFromRawPrivateKey(RawPrivateKey privateKey, Random random) throws FoundationException;

    public native java.nio.ByteBuffer ecies_new();

    public native void ecies_close(java.nio.ByteBuffer cCtx);

    public native void ecies_setRandom(java.nio.ByteBuffer cCtx, Random random);

    public native void ecies_setCipher(java.nio.ByteBuffer cCtx, Cipher cipher);

    public native void ecies_setMac(java.nio.ByteBuffer cCtx, Mac mac);

    public native void ecies_setKdf(java.nio.ByteBuffer cCtx, Kdf kdf);

    /*
    * Set ephemeral key that used for data encryption.
    * Public and ephemeral keys should belong to the same curve.
    * This dependency is optional.
    */
    public native void ecies_setEphemeralKey(java.nio.ByteBuffer cCtx, PrivateKey ephemeralKey);

    /*
    * Set weak reference to the key algorithm.
    * Key algorithm MUST support shared key computation as well.
    */
    public native void ecies_setKeyAlg(java.nio.ByteBuffer cCtx, KeyAlg keyAlg);

    /*
    * Release weak reference to the key algorithm.
    */
    public native void ecies_releaseKeyAlg(java.nio.ByteBuffer cCtx);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ecies_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies
    * except random.
    */
    public native void ecies_setupDefaultsNoRandom(java.nio.ByteBuffer cCtx);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ecies_encryptedLen(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] ecies_encrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ecies_decryptedLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ecies_decrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    public native java.nio.ByteBuffer recipientCipher_new();

    public native void recipientCipher_close(java.nio.ByteBuffer cCtx);

    public native void recipientCipher_setRandom(java.nio.ByteBuffer cCtx, Random random);

    public native void recipientCipher_setEncryptionCipher(java.nio.ByteBuffer cCtx, Cipher encryptionCipher);

    /*
    * Add recipient defined with id and public key.
    */
    public native void recipientCipher_addKeyRecipient(java.nio.ByteBuffer cCtx, byte[] recipientId, PublicKey publicKey);

    /*
    * Remove all recipients.
    */
    public native void recipientCipher_clearRecipients(java.nio.ByteBuffer cCtx);

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    */
    public native MessageInfoCustomParams recipientCipher_customParams(java.nio.ByteBuffer cCtx);

    /*
    * Return buffer length required to hold message info returned by the
    * "start encryption" method.
    * Precondition: all recipients and custom parameters should be set.
    */
    public native int recipientCipher_messageInfoLen(java.nio.ByteBuffer cCtx);

    /*
    * Start encryption process.
    */
    public native void recipientCipher_startEncryption(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Return serialized message info to the buffer.
    *
    * Precondition: this method can be called after "start encryption".
    * Precondition: this method can be called before "finish encryption".
    *
    * Note, store message info to use it for decryption process,
    * or place it at the encrypted data beginning (embedding).
    *
    * Return message info - recipients public information,
    * algorithm information, etc.
    */
    public native byte[] recipientCipher_packMessageInfo(java.nio.ByteBuffer cCtx);

    /*
    * Return buffer length required to hold output of the method
    * "process encryption" and method "finish" during encryption.
    */
    public native int recipientCipher_encryptionOutLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Process encryption of a new portion of data.
    */
    public native byte[] recipientCipher_processEncryption(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Accomplish encryption.
    */
    public native byte[] recipientCipher_finishEncryption(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Initiate decryption process with a recipient private key.
    * Message info can be empty if it was embedded to encrypted data.
    */
    public native void recipientCipher_startDecryptionWithKey(java.nio.ByteBuffer cCtx, byte[] recipientId, PrivateKey privateKey, byte[] messageInfo) throws FoundationException;

    /*
    * Return buffer length required to hold output of the method
    * "process decryption" and method "finish" during decryption.
    */
    public native int recipientCipher_decryptionOutLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Process with a new portion of data.
    * Return error if data can not be encrypted or decrypted.
    */
    public native byte[] recipientCipher_processDecryption(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Accomplish decryption.
    */
    public native byte[] recipientCipher_finishDecryption(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer messageInfoCustomParams_new();

    public native void messageInfoCustomParams_close(java.nio.ByteBuffer cCtx);

    /*
    * Add custom parameter with integer value.
    */
    public native void messageInfoCustomParams_addInt(java.nio.ByteBuffer cCtx, byte[] key, int value);

    /*
    * Add custom parameter with UTF8 string value.
    */
    public native void messageInfoCustomParams_addString(java.nio.ByteBuffer cCtx, byte[] key, byte[] value);

    /*
    * Add custom parameter with octet string value.
    */
    public native void messageInfoCustomParams_addData(java.nio.ByteBuffer cCtx, byte[] key, byte[] value);

    /*
    * Remove all parameters.
    */
    public native void messageInfoCustomParams_clear(java.nio.ByteBuffer cCtx);

    /*
    * Return custom parameter with integer value.
    */
    public native int messageInfoCustomParams_findInt(java.nio.ByteBuffer cCtx, byte[] key) throws FoundationException;

    /*
    * Return custom parameter with UTF8 string value.
    */
    public native byte[] messageInfoCustomParams_findString(java.nio.ByteBuffer cCtx, byte[] key) throws FoundationException;

    /*
    * Return custom parameter with octet string value.
    */
    public native byte[] messageInfoCustomParams_findData(java.nio.ByteBuffer cCtx, byte[] key) throws FoundationException;

    public native java.nio.ByteBuffer keyProvider_new();

    public native void keyProvider_close(java.nio.ByteBuffer cCtx);

    public native void keyProvider_setRandom(java.nio.ByteBuffer cCtx, Random random);

    public native void keyProvider_setEcies(java.nio.ByteBuffer cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void keyProvider_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Setup parameters that is used during RSA key generation.
    */
    public native void keyProvider_setRsaParams(java.nio.ByteBuffer cCtx, int bitlen);

    /*
    * Generate new private key from the given id.
    */
    public native PrivateKey keyProvider_generatePrivateKey(java.nio.ByteBuffer cCtx, AlgId algId) throws FoundationException;

    /*
    * Import private key from the PKCS#8 format.
    */
    public native PrivateKey keyProvider_importPrivateKey(java.nio.ByteBuffer cCtx, byte[] keyData) throws FoundationException;

    /*
    * Import public key from the PKCS#8 format.
    */
    public native PublicKey keyProvider_importPublicKey(java.nio.ByteBuffer cCtx, byte[] keyData) throws FoundationException;

    /*
    * Calculate buffer size enough to hold exported public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int keyProvider_exportedPublicKeyLen(java.nio.ByteBuffer cCtx, PublicKey publicKey);

    /*
    * Export given public key to the PKCS#8 DER format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] keyProvider_exportPublicKey(java.nio.ByteBuffer cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold exported private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int keyProvider_exportedPrivateKeyLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey);

    /*
    * Export given private key to the PKCS#8 or SEC1 DER format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] keyProvider_exportPrivateKey(java.nio.ByteBuffer cCtx, PrivateKey privateKey) throws FoundationException;

    public native java.nio.ByteBuffer signer_new();

    public native void signer_close(java.nio.ByteBuffer cCtx);

    public native void signer_setHash(java.nio.ByteBuffer cCtx, Hash hash);

    public native void signer_setRandom(java.nio.ByteBuffer cCtx, Random random);

    /*
    * Start a processing a new signature.
    */
    public native void signer_reset(java.nio.ByteBuffer cCtx);

    /*
    * Add given data to the signed data.
    */
    public native void signer_appendData(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Return length of the signature.
    */
    public native int signer_signatureLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey);

    /*
    * Accomplish signing and return signature.
    */
    public native byte[] signer_sign(java.nio.ByteBuffer cCtx, PrivateKey privateKey) throws FoundationException;

    public native java.nio.ByteBuffer verifier_new();

    public native void verifier_close(java.nio.ByteBuffer cCtx);

    /*
    * Start verifying a signature.
    */
    public native void verifier_reset(java.nio.ByteBuffer cCtx, byte[] signature) throws FoundationException;

    /*
    * Add given data to the signed data.
    */
    public native void verifier_appendData(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Verify accumulated data.
    */
    public native boolean verifier_verify(java.nio.ByteBuffer cCtx, PublicKey publicKey);

    public native java.nio.ByteBuffer brainkeyClient_new();

    public native void brainkeyClient_close(java.nio.ByteBuffer cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void brainkeyClient_setRandom(java.nio.ByteBuffer cCtx, Random random);

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void brainkeyClient_setOperationRandom(java.nio.ByteBuffer cCtx, Random operationRandom);

    public native void brainkeyClient_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native BrainkeyClientBlindResult brainkeyClient_blind(java.nio.ByteBuffer cCtx, byte[] password) throws FoundationException;

    public native byte[] brainkeyClient_deblind(java.nio.ByteBuffer cCtx, byte[] password, byte[] hardenedPoint, byte[] deblindFactor, byte[] keyName) throws FoundationException;

    public native java.nio.ByteBuffer brainkeyServer_new();

    public native void brainkeyServer_close(java.nio.ByteBuffer cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void brainkeyServer_setRandom(java.nio.ByteBuffer cCtx, Random random);

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void brainkeyServer_setOperationRandom(java.nio.ByteBuffer cCtx, Random operationRandom);

    public native void brainkeyServer_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native byte[] brainkeyServer_generateIdentitySecret(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native byte[] brainkeyServer_harden(java.nio.ByteBuffer cCtx, byte[] identitySecret, byte[] blindedPoint) throws FoundationException;

    public native java.nio.ByteBuffer groupSessionMessage_new();

    public native void groupSessionMessage_close(java.nio.ByteBuffer cCtx);

    /*
    * Returns message type.
    */
    public native GroupMsgType groupSessionMessage_getType(java.nio.ByteBuffer cCtx);

    /*
    * Returns session id.
    * This method should be called only for group info type.
    */
    public native byte[] groupSessionMessage_getSessionId(java.nio.ByteBuffer cCtx);

    /*
    * Returns message epoch.
    */
    public native long groupSessionMessage_getEpoch(java.nio.ByteBuffer cCtx);

    /*
    * Buffer len to serialize this class.
    */
    public native int groupSessionMessage_serializeLen(java.nio.ByteBuffer cCtx);

    /*
    * Serializes instance.
    */
    public native byte[] groupSessionMessage_serialize(java.nio.ByteBuffer cCtx);

    /*
    * Deserializes instance.
    */
    public native GroupSessionMessage groupSessionMessage_deserialize(byte[] input) throws FoundationException;

    public native java.nio.ByteBuffer groupSessionTicket_new();

    public native void groupSessionTicket_close(java.nio.ByteBuffer cCtx);

    /*
    * Random used to generate keys
    */
    public native void groupSessionTicket_setRng(java.nio.ByteBuffer cCtx, Random rng);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void groupSessionTicket_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Set this ticket to start new group session.
    */
    public native void groupSessionTicket_setupTicketAsNew(java.nio.ByteBuffer cCtx, byte[] sessionId) throws FoundationException;

    /*
    * Returns message that should be sent to all participants using secure channel.
    */
    public native GroupSessionMessage groupSessionTicket_getTicketMessage(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer groupSession_new();

    public native void groupSession_close(java.nio.ByteBuffer cCtx);

    /*
    * Random
    */
    public native void groupSession_setRng(java.nio.ByteBuffer cCtx, Random rng) throws FoundationException;

    /*
    * Returns current epoch.
    */
    public native long groupSession_getCurrentEpoch(java.nio.ByteBuffer cCtx);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void groupSession_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Returns session id.
    */
    public native byte[] groupSession_getSessionId(java.nio.ByteBuffer cCtx);

    /*
    * Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
    * Epoch message should be encrypted and signed by trusted group chat member (admin).
    */
    public native void groupSession_addEpoch(java.nio.ByteBuffer cCtx, GroupSessionMessage message) throws FoundationException;

    /*
    * Encrypts data
    */
    public native GroupSessionMessage groupSession_encrypt(java.nio.ByteBuffer cCtx, byte[] plainText, PrivateKey privateKey) throws FoundationException;

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public native int groupSession_decryptLen(java.nio.ByteBuffer cCtx, GroupSessionMessage message);

    /*
    * Decrypts message
    */
    public native byte[] groupSession_decrypt(java.nio.ByteBuffer cCtx, GroupSessionMessage message, PublicKey publicKey) throws FoundationException;

    /*
    * Creates ticket with new key for removing participants or proactive to rotate encryption key.
    */
    public native GroupSessionTicket groupSession_createGroupTicket(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer sha224_new();

    public native void sha224_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha224_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha224_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha224_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha224_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha224_start(java.nio.ByteBuffer cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha224_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha224_finish(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer sha256_new();

    public native void sha256_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha256_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha256_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha256_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha256_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha256_start(java.nio.ByteBuffer cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha256_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha256_finish(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer sha384_new();

    public native void sha384_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha384_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha384_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha384_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha384_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha384_start(java.nio.ByteBuffer cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha384_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha384_finish(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer sha512_new();

    public native void sha512_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha512_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha512_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha512_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha512_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha512_start(java.nio.ByteBuffer cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha512_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha512_finish(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer aes256Gcm_new();

    public native void aes256Gcm_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId aes256Gcm_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo aes256Gcm_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void aes256Gcm_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Encrypt given data.
    */
    public native byte[] aes256Gcm_encrypt(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int aes256Gcm_encryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] aes256Gcm_decrypt(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int aes256Gcm_decryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Setup IV or nonce.
    */
    public native void aes256Gcm_setNonce(java.nio.ByteBuffer cCtx, byte[] nonce);

    /*
    * Set cipher encryption / decryption key.
    */
    public native void aes256Gcm_setKey(java.nio.ByteBuffer cCtx, byte[] key);

    /*
    * Start sequential encryption.
    */
    public native void aes256Gcm_startEncryption(java.nio.ByteBuffer cCtx);

    /*
    * Start sequential decryption.
    */
    public native void aes256Gcm_startDecryption(java.nio.ByteBuffer cCtx);

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public native byte[] aes256Gcm_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Gcm_outLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Gcm_encryptedOutLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Gcm_decryptedOutLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Accomplish encryption or decryption process.
    */
    public native byte[] aes256Gcm_finish(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Encrypt given data.
    * If 'tag' is not given, then it will written to the 'enc'.
    */
    public native AuthEncryptAuthEncryptResult aes256Gcm_authEncrypt(java.nio.ByteBuffer cCtx, byte[] data, byte[] authData) throws FoundationException;

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
    */
    public native int aes256Gcm_authEncryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Decrypt given data.
    * If 'tag' is not given, then it will be taken from the 'enc'.
    */
    public native byte[] aes256Gcm_authDecrypt(java.nio.ByteBuffer cCtx, byte[] data, byte[] authData, byte[] tag) throws FoundationException;

    /*
    * Calculate required buffer length to hold the authenticated decrypted data.
    */
    public native int aes256Gcm_authDecryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    public native java.nio.ByteBuffer aes256Cbc_new();

    public native void aes256Cbc_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId aes256Cbc_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo aes256Cbc_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void aes256Cbc_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Encrypt given data.
    */
    public native byte[] aes256Cbc_encrypt(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int aes256Cbc_encryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] aes256Cbc_decrypt(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int aes256Cbc_decryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Setup IV or nonce.
    */
    public native void aes256Cbc_setNonce(java.nio.ByteBuffer cCtx, byte[] nonce);

    /*
    * Set cipher encryption / decryption key.
    */
    public native void aes256Cbc_setKey(java.nio.ByteBuffer cCtx, byte[] key);

    /*
    * Start sequential encryption.
    */
    public native void aes256Cbc_startEncryption(java.nio.ByteBuffer cCtx);

    /*
    * Start sequential decryption.
    */
    public native void aes256Cbc_startDecryption(java.nio.ByteBuffer cCtx);

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public native byte[] aes256Cbc_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Cbc_outLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Cbc_encryptedOutLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Cbc_decryptedOutLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Accomplish encryption or decryption process.
    */
    public native byte[] aes256Cbc_finish(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer asn1rd_new();

    public native void asn1rd_close(java.nio.ByteBuffer cCtx);

    /*
    * Reset all internal states and prepare to new ASN.1 reading operations.
    */
    public native void asn1rd_reset(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Return length in bytes how many bytes are left for reading.
    */
    public native int asn1rd_leftLen(java.nio.ByteBuffer cCtx);

    /*
    * Return true if status is not "success".
    */
    public native boolean asn1rd_hasError(java.nio.ByteBuffer cCtx);

    /*
    * Return error code.
    */
    public native void asn1rd_status(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Get tag of the current ASN.1 element.
    */
    public native int asn1rd_getTag(java.nio.ByteBuffer cCtx);

    /*
    * Get length of the current ASN.1 element.
    */
    public native int asn1rd_getLen(java.nio.ByteBuffer cCtx);

    /*
    * Get length of the current ASN.1 element with tag and length itself.
    */
    public native int asn1rd_getDataLen(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: TAG.
    * Return element length.
    */
    public native int asn1rd_readTag(java.nio.ByteBuffer cCtx, int tag);

    /*
    * Read ASN.1 type: context-specific TAG.
    * Return element length.
    * Return 0 if current position do not points to the requested tag.
    */
    public native int asn1rd_readContextTag(java.nio.ByteBuffer cCtx, int tag);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native int asn1rd_readInt(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native byte asn1rd_readInt8(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native short asn1rd_readInt16(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native int asn1rd_readInt32(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readInt64(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readUint(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native short asn1rd_readUint8(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native int asn1rd_readUint16(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readUint32(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readUint64(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: BOOLEAN.
    */
    public native boolean asn1rd_readBool(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: NULL.
    */
    public native void asn1rd_readNull(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: NULL, only if it exists.
    * Note, this method is safe to call even no more data is left for reading.
    */
    public native void asn1rd_readNullOptional(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: OCTET STRING.
    */
    public native byte[] asn1rd_readOctetStr(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: BIT STRING.
    */
    public native byte[] asn1rd_readBitstringAsOctetStr(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: UTF8String.
    */
    public native byte[] asn1rd_readUtf8Str(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: OID.
    */
    public native byte[] asn1rd_readOid(java.nio.ByteBuffer cCtx);

    /*
    * Read raw data of given length.
    */
    public native byte[] asn1rd_readData(java.nio.ByteBuffer cCtx, int len);

    /*
    * Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    * Return element length.
    */
    public native int asn1rd_readSequence(java.nio.ByteBuffer cCtx);

    /*
    * Read ASN.1 type: CONSTRUCTED | SET.
    * Return element length.
    */
    public native int asn1rd_readSet(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer asn1wr_new();

    public native void asn1wr_close(java.nio.ByteBuffer cCtx);

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
    */
    public native void asn1wr_reset(java.nio.ByteBuffer cCtx, byte[] out, int outLen);

    /*
    * Finalize writing and forbid further operations.
    *
    * Note, that ASN.1 structure is always written to the buffer end, and
    * if argument "do not adjust" is false, then data is moved to the
    * beginning, otherwise - data is left at the buffer end.
    *
    * Returns length of the written bytes.
    */
    public native int asn1wr_finish(java.nio.ByteBuffer cCtx, boolean doNotAdjust);

    /*
    * Returns pointer to the inner buffer.
    */
    public native byte asn1wr_bytes(java.nio.ByteBuffer cCtx);

    /*
    * Returns total inner buffer length.
    */
    public native int asn1wr_len(java.nio.ByteBuffer cCtx);

    /*
    * Returns how many bytes were already written to the ASN.1 structure.
    */
    public native int asn1wr_writtenLen(java.nio.ByteBuffer cCtx);

    /*
    * Returns how many bytes are available for writing.
    */
    public native int asn1wr_unwrittenLen(java.nio.ByteBuffer cCtx);

    /*
    * Return true if status is not "success".
    */
    public native boolean asn1wr_hasError(java.nio.ByteBuffer cCtx);

    /*
    * Return error code.
    */
    public native void asn1wr_status(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
    */
    public native byte asn1wr_reserve(java.nio.ByteBuffer cCtx, int len);

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
    */
    public native int asn1wr_writeTag(java.nio.ByteBuffer cCtx, int tag);

    /*
    * Write context-specific ASN.1 tag.
    * Return count of written bytes.
    */
    public native int asn1wr_writeContextTag(java.nio.ByteBuffer cCtx, int tag, int len);

    /*
    * Write length of the following data.
    * Return count of written bytes.
    */
    public native int asn1wr_writeLen(java.nio.ByteBuffer cCtx, int len);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt(java.nio.ByteBuffer cCtx, int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt8(java.nio.ByteBuffer cCtx, byte value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt16(java.nio.ByteBuffer cCtx, short value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt32(java.nio.ByteBuffer cCtx, int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt64(java.nio.ByteBuffer cCtx, long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint(java.nio.ByteBuffer cCtx, long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint8(java.nio.ByteBuffer cCtx, short value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint16(java.nio.ByteBuffer cCtx, int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint32(java.nio.ByteBuffer cCtx, long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint64(java.nio.ByteBuffer cCtx, long value);

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
    */
    public native int asn1wr_writeBool(java.nio.ByteBuffer cCtx, boolean value);

    /*
    * Write ASN.1 type: NULL.
    */
    public native int asn1wr_writeNull(java.nio.ByteBuffer cCtx);

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
    */
    public native int asn1wr_writeOctetStr(java.nio.ByteBuffer cCtx, byte[] value);

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
    */
    public native int asn1wr_writeOctetStrAsBitstring(java.nio.ByteBuffer cCtx, byte[] value);

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
    */
    public native int asn1wr_writeData(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUtf8Str(java.nio.ByteBuffer cCtx, byte[] value);

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
    */
    public native int asn1wr_writeOid(java.nio.ByteBuffer cCtx, byte[] value);

    /*
    * Mark previously written data of given length as ASN.1 type: SQUENCE.
    * Return count of written bytes.
    */
    public native int asn1wr_writeSequence(java.nio.ByteBuffer cCtx, int len);

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    */
    public native int asn1wr_writeSet(java.nio.ByteBuffer cCtx, int len);

    /*
    * Return public key exponent.
    */
    public native int rsaPublicKey_keyExponent(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer rsaPublicKey_new();

    public native void rsaPublicKey_close(java.nio.ByteBuffer cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rsaPublicKey_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rsaPublicKey_algInfo(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rsaPublicKey_len(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rsaPublicKey_bitlen(java.nio.ByteBuffer cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rsaPublicKey_isValid(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer rsaPrivateKey_new();

    public native void rsaPrivateKey_close(java.nio.ByteBuffer cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rsaPrivateKey_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rsaPrivateKey_algInfo(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rsaPrivateKey_len(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rsaPrivateKey_bitlen(java.nio.ByteBuffer cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rsaPrivateKey_isValid(java.nio.ByteBuffer cCtx);

    /*
    * Extract public key from the private key.
    */
    public native PublicKey rsaPrivateKey_extractPublicKey(java.nio.ByteBuffer cCtx);

    public native void rsa_setRandom(java.nio.ByteBuffer cCtx, Random random);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void rsa_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey rsa_generateKey(java.nio.ByteBuffer cCtx, int bitlen) throws FoundationException;

    public native java.nio.ByteBuffer rsa_new();

    public native void rsa_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId rsa_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo rsa_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void rsa_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey rsa_generateEphemeralKey(java.nio.ByteBuffer cCtx, Key key) throws FoundationException;

    /*
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native PublicKey rsa_importPublicKey(java.nio.ByteBuffer cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey rsa_exportPublicKey(java.nio.ByteBuffer cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native PrivateKey rsa_importPrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey rsa_exportPrivateKey(java.nio.ByteBuffer cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean rsa_canEncrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int rsa_encryptedLen(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] rsa_encrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean rsa_canDecrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int rsa_decryptedLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] rsa_decrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean rsa_canSign(java.nio.ByteBuffer cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int rsa_signatureLen(java.nio.ByteBuffer cCtx, Key key);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] rsa_signHash(java.nio.ByteBuffer cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean rsa_canVerify(java.nio.ByteBuffer cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean rsa_verifyHash(java.nio.ByteBuffer cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    public native java.nio.ByteBuffer eccPublicKey_new();

    public native void eccPublicKey_close(java.nio.ByteBuffer cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId eccPublicKey_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo eccPublicKey_algInfo(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int eccPublicKey_len(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bits.
    */
    public native int eccPublicKey_bitlen(java.nio.ByteBuffer cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean eccPublicKey_isValid(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer eccPrivateKey_new();

    public native void eccPrivateKey_close(java.nio.ByteBuffer cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId eccPrivateKey_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo eccPrivateKey_algInfo(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int eccPrivateKey_len(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bits.
    */
    public native int eccPrivateKey_bitlen(java.nio.ByteBuffer cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean eccPrivateKey_isValid(java.nio.ByteBuffer cCtx);

    /*
    * Extract public key from the private key.
    */
    public native PublicKey eccPrivateKey_extractPublicKey(java.nio.ByteBuffer cCtx);

    public native void ecc_setRandom(java.nio.ByteBuffer cCtx, Random random);

    public native void ecc_setEcies(java.nio.ByteBuffer cCtx, Ecies ecies) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ecc_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Supported algorithm ids:
    * - secp256r1.
    *
    * Note, this operation might be slow.
    */
    public native PrivateKey ecc_generateKey(java.nio.ByteBuffer cCtx, AlgId algId) throws FoundationException;

    public native java.nio.ByteBuffer ecc_new();

    public native void ecc_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ecc_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo ecc_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void ecc_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey ecc_generateEphemeralKey(java.nio.ByteBuffer cCtx, Key key) throws FoundationException;

    /*
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native PublicKey ecc_importPublicKey(java.nio.ByteBuffer cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey ecc_exportPublicKey(java.nio.ByteBuffer cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native PrivateKey ecc_importPrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey ecc_exportPrivateKey(java.nio.ByteBuffer cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean ecc_canEncrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ecc_encryptedLen(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] ecc_encrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean ecc_canDecrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ecc_decryptedLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ecc_decrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean ecc_canSign(java.nio.ByteBuffer cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int ecc_signatureLen(java.nio.ByteBuffer cCtx, Key key);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] ecc_signHash(java.nio.ByteBuffer cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean ecc_canVerify(java.nio.ByteBuffer cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean ecc_verifyHash(java.nio.ByteBuffer cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public native byte[] ecc_computeSharedKey(java.nio.ByteBuffer cCtx, PublicKey publicKey, PrivateKey privateKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public native int ecc_sharedKeyLen(java.nio.ByteBuffer cCtx, Key key);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void entropyAccumulator_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Add given entropy source to the accumulator.
    * Threshold defines minimum number of bytes that must be gathered
    * from the source during accumulation.
    */
    public native void entropyAccumulator_addSource(java.nio.ByteBuffer cCtx, EntropySource source, int threshold);

    public native java.nio.ByteBuffer entropyAccumulator_new();

    public native void entropyAccumulator_close(java.nio.ByteBuffer cCtx);

    /*
    * Defines that implemented source is strong.
    */
    public native boolean entropyAccumulator_isStrong(java.nio.ByteBuffer cCtx);

    /*
    * Gather entropy of the requested length.
    */
    public native byte[] entropyAccumulator_gather(java.nio.ByteBuffer cCtx, int len) throws FoundationException;

    public native void ctrDrbg_setEntropySource(java.nio.ByteBuffer cCtx, EntropySource entropySource) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ctrDrbg_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Force entropy to be gathered at the beginning of every call to
    * the random() method.
    * Note, use this if your entropy source has sufficient throughput.
    */
    public native void ctrDrbg_enablePredictionResistance(java.nio.ByteBuffer cCtx);

    /*
    * Sets the reseed interval.
    * Default value is reseed interval.
    */
    public native void ctrDrbg_setReseedInterval(java.nio.ByteBuffer cCtx, int interval);

    /*
    * Sets the amount of entropy grabbed on each seed or reseed.
    * The default value is entropy len.
    */
    public native void ctrDrbg_setEntropyLen(java.nio.ByteBuffer cCtx, int len);

    public native java.nio.ByteBuffer ctrDrbg_new();

    public native void ctrDrbg_close(java.nio.ByteBuffer cCtx);

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public native byte[] ctrDrbg_random(java.nio.ByteBuffer cCtx, int dataLen) throws FoundationException;

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public native void ctrDrbg_reseed(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native void hmac_setHash(java.nio.ByteBuffer cCtx, Hash hash);

    public native java.nio.ByteBuffer hmac_new();

    public native void hmac_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId hmac_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo hmac_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void hmac_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Size of the digest (mac output) in bytes.
    */
    public native int hmac_digestLen(java.nio.ByteBuffer cCtx);

    /*
    * Calculate MAC over given data.
    */
    public native byte[] hmac_mac(java.nio.ByteBuffer cCtx, byte[] key, byte[] data);

    /*
    * Start a new MAC.
    */
    public native void hmac_start(java.nio.ByteBuffer cCtx, byte[] key);

    /*
    * Add given data to the MAC.
    */
    public native void hmac_update(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Accomplish MAC and return it's result (a message digest).
    */
    public native byte[] hmac_finish(java.nio.ByteBuffer cCtx);

    /*
    * Prepare to authenticate a new message with the same key
    * as the previous MAC operation.
    */
    public native void hmac_reset(java.nio.ByteBuffer cCtx);

    public native void hkdf_setHash(java.nio.ByteBuffer cCtx, Hash hash);

    public native java.nio.ByteBuffer hkdf_new();

    public native void hkdf_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId hkdf_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo hkdf_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void hkdf_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] hkdf_derive(java.nio.ByteBuffer cCtx, byte[] data, int keyLen);

    /*
    * Prepare algorithm to derive new key.
    */
    public native void hkdf_reset(java.nio.ByteBuffer cCtx, byte[] salt, int iterationCount);

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    public native void hkdf_setInfo(java.nio.ByteBuffer cCtx, byte[] info);

    public native void kdf1_setHash(java.nio.ByteBuffer cCtx, Hash hash);

    public native java.nio.ByteBuffer kdf1_new();

    public native void kdf1_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId kdf1_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo kdf1_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void kdf1_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] kdf1_derive(java.nio.ByteBuffer cCtx, byte[] data, int keyLen);

    public native void kdf2_setHash(java.nio.ByteBuffer cCtx, Hash hash);

    public native java.nio.ByteBuffer kdf2_new();

    public native void kdf2_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId kdf2_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo kdf2_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void kdf2_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] kdf2_derive(java.nio.ByteBuffer cCtx, byte[] data, int keyLen);

    /*
    * Configure random number generator to generate sequence filled with given byte.
    */
    public native void fakeRandom_setupSourceByte(java.nio.ByteBuffer cCtx, byte byteSource);

    /*
    * Configure random number generator to generate random sequence from given data.
    * Note, that given data is used as circular source.
    */
    public native void fakeRandom_setupSourceData(java.nio.ByteBuffer cCtx, byte[] dataSource);

    public native java.nio.ByteBuffer fakeRandom_new();

    public native void fakeRandom_close(java.nio.ByteBuffer cCtx);

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public native byte[] fakeRandom_random(java.nio.ByteBuffer cCtx, int dataLen) throws FoundationException;

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public native void fakeRandom_reseed(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Defines that implemented source is strong.
    */
    public native boolean fakeRandom_isStrong(java.nio.ByteBuffer cCtx);

    /*
    * Gather entropy of the requested length.
    */
    public native byte[] fakeRandom_gather(java.nio.ByteBuffer cCtx, int len) throws FoundationException;

    public native void pkcs5Pbkdf2_setHmac(java.nio.ByteBuffer cCtx, Mac hmac);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void pkcs5Pbkdf2_setupDefaults(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer pkcs5Pbkdf2_new();

    public native void pkcs5Pbkdf2_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId pkcs5Pbkdf2_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo pkcs5Pbkdf2_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void pkcs5Pbkdf2_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] pkcs5Pbkdf2_derive(java.nio.ByteBuffer cCtx, byte[] data, int keyLen);

    /*
    * Prepare algorithm to derive new key.
    */
    public native void pkcs5Pbkdf2_reset(java.nio.ByteBuffer cCtx, byte[] salt, int iterationCount);

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    public native void pkcs5Pbkdf2_setInfo(java.nio.ByteBuffer cCtx, byte[] info);

    public native void pkcs5Pbes2_setKdf(java.nio.ByteBuffer cCtx, SaltedKdf kdf);

    public native void pkcs5Pbes2_setCipher(java.nio.ByteBuffer cCtx, Cipher cipher);

    /*
    * Configure cipher with a new password.
    */
    public native void pkcs5Pbes2_reset(java.nio.ByteBuffer cCtx, byte[] pwd);

    public native java.nio.ByteBuffer pkcs5Pbes2_new();

    public native void pkcs5Pbes2_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId pkcs5Pbes2_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo pkcs5Pbes2_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void pkcs5Pbes2_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Encrypt given data.
    */
    public native byte[] pkcs5Pbes2_encrypt(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int pkcs5Pbes2_encryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] pkcs5Pbes2_decrypt(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int pkcs5Pbes2_decryptedLen(java.nio.ByteBuffer cCtx, int dataLen);

    /*
    * Set a new seed as an entropy source.
    */
    public native void seedEntropySource_resetSeed(java.nio.ByteBuffer cCtx, byte[] seed);

    public native java.nio.ByteBuffer seedEntropySource_new();

    public native void seedEntropySource_close(java.nio.ByteBuffer cCtx);

    /*
    * Defines that implemented source is strong.
    */
    public native boolean seedEntropySource_isStrong(java.nio.ByteBuffer cCtx);

    /*
    * Gather entropy of the requested length.
    */
    public native byte[] seedEntropySource_gather(java.nio.ByteBuffer cCtx, int len) throws FoundationException;

    /*
    * Set a new key material.
    */
    public native void keyMaterialRng_resetKeyMaterial(java.nio.ByteBuffer cCtx, byte[] keyMaterial);

    public native java.nio.ByteBuffer keyMaterialRng_new();

    public native void keyMaterialRng_close(java.nio.ByteBuffer cCtx);

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public native byte[] keyMaterialRng_random(java.nio.ByteBuffer cCtx, int dataLen) throws FoundationException;

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public native void keyMaterialRng_reseed(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Return key data.
    */
    public native byte[] rawPublicKey_data(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer rawPublicKey_new();

    public native void rawPublicKey_close(java.nio.ByteBuffer cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rawPublicKey_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rawPublicKey_algInfo(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rawPublicKey_len(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rawPublicKey_bitlen(java.nio.ByteBuffer cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rawPublicKey_isValid(java.nio.ByteBuffer cCtx);

    /*
    * Return key data.
    */
    public native byte[] rawPrivateKey_data(java.nio.ByteBuffer cCtx);

    /*
    * Return true if private key contains public key.
    */
    public native boolean rawPrivateKey_hasPublicKey(java.nio.ByteBuffer cCtx);

    /*
    * Setup public key related to the private key.
    */
    public native void rawPrivateKey_setPublicKey(java.nio.ByteBuffer cCtx, RawPublicKey rawPublicKey);

    /*
    * Return public key related to the private key.
    */
    public native RawPublicKey rawPrivateKey_getPublicKey(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer rawPrivateKey_new();

    public native void rawPrivateKey_close(java.nio.ByteBuffer cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rawPrivateKey_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rawPrivateKey_algInfo(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rawPrivateKey_len(java.nio.ByteBuffer cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rawPrivateKey_bitlen(java.nio.ByteBuffer cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rawPrivateKey_isValid(java.nio.ByteBuffer cCtx);

    /*
    * Extract public key from the private key.
    */
    public native PublicKey rawPrivateKey_extractPublicKey(java.nio.ByteBuffer cCtx);

    public native void pkcs8Serializer_setAsn1Writer(java.nio.ByteBuffer cCtx, Asn1Writer asn1Writer);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void pkcs8Serializer_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Serialize Public Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int pkcs8Serializer_serializePublicKeyInplace(java.nio.ByteBuffer cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int pkcs8Serializer_serializePrivateKeyInplace(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native java.nio.ByteBuffer pkcs8Serializer_new();

    public native void pkcs8Serializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int pkcs8Serializer_serializedPublicKeyLen(java.nio.ByteBuffer cCtx, RawPublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] pkcs8Serializer_serializePublicKey(java.nio.ByteBuffer cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int pkcs8Serializer_serializedPrivateKeyLen(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] pkcs8Serializer_serializePrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native void sec1Serializer_setAsn1Writer(java.nio.ByteBuffer cCtx, Asn1Writer asn1Writer) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void sec1Serializer_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Serialize Public Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int sec1Serializer_serializePublicKeyInplace(java.nio.ByteBuffer cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int sec1Serializer_serializePrivateKeyInplace(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native java.nio.ByteBuffer sec1Serializer_new();

    public native void sec1Serializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int sec1Serializer_serializedPublicKeyLen(java.nio.ByteBuffer cCtx, RawPublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] sec1Serializer_serializePublicKey(java.nio.ByteBuffer cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int sec1Serializer_serializedPrivateKeyLen(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] sec1Serializer_serializePrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native void keyAsn1Serializer_setAsn1Writer(java.nio.ByteBuffer cCtx, Asn1Writer asn1Writer) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void keyAsn1Serializer_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Serialize Public Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int keyAsn1Serializer_serializePublicKeyInplace(java.nio.ByteBuffer cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int keyAsn1Serializer_serializePrivateKeyInplace(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native java.nio.ByteBuffer keyAsn1Serializer_new();

    public native void keyAsn1Serializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int keyAsn1Serializer_serializedPublicKeyLen(java.nio.ByteBuffer cCtx, RawPublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] keyAsn1Serializer_serializePublicKey(java.nio.ByteBuffer cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int keyAsn1Serializer_serializedPrivateKeyLen(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] keyAsn1Serializer_serializePrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native void keyAsn1Deserializer_setAsn1Reader(java.nio.ByteBuffer cCtx, Asn1Reader asn1Reader) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void keyAsn1Deserializer_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Deserialize Public Key by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native RawPublicKey keyAsn1Deserializer_deserializePublicKeyInplace(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Deserialize Private Key by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native RawPrivateKey keyAsn1Deserializer_deserializePrivateKeyInplace(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer keyAsn1Deserializer_new();

    public native void keyAsn1Deserializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Deserialize given public key as an interchangeable format to the object.
    */
    public native RawPublicKey keyAsn1Deserializer_deserializePublicKey(java.nio.ByteBuffer cCtx, byte[] publicKeyData) throws FoundationException;

    /*
    * Deserialize given private key as an interchangeable format to the object.
    */
    public native RawPrivateKey keyAsn1Deserializer_deserializePrivateKey(java.nio.ByteBuffer cCtx, byte[] privateKeyData) throws FoundationException;

    public native void ed25519_setRandom(java.nio.ByteBuffer cCtx, Random random);

    public native void ed25519_setEcies(java.nio.ByteBuffer cCtx, Ecies ecies) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ed25519_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey ed25519_generateKey(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer ed25519_new();

    public native void ed25519_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ed25519_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo ed25519_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void ed25519_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey ed25519_generateEphemeralKey(java.nio.ByteBuffer cCtx, Key key) throws FoundationException;

    /*
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native PublicKey ed25519_importPublicKey(java.nio.ByteBuffer cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey ed25519_exportPublicKey(java.nio.ByteBuffer cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native PrivateKey ed25519_importPrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey ed25519_exportPrivateKey(java.nio.ByteBuffer cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean ed25519_canEncrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ed25519_encryptedLen(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] ed25519_encrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean ed25519_canDecrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ed25519_decryptedLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ed25519_decrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean ed25519_canSign(java.nio.ByteBuffer cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int ed25519_signatureLen(java.nio.ByteBuffer cCtx, Key key);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] ed25519_signHash(java.nio.ByteBuffer cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean ed25519_canVerify(java.nio.ByteBuffer cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean ed25519_verifyHash(java.nio.ByteBuffer cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public native byte[] ed25519_computeSharedKey(java.nio.ByteBuffer cCtx, PublicKey publicKey, PrivateKey privateKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public native int ed25519_sharedKeyLen(java.nio.ByteBuffer cCtx, Key key);

    public native void curve25519_setRandom(java.nio.ByteBuffer cCtx, Random random);

    public native void curve25519_setEcies(java.nio.ByteBuffer cCtx, Ecies ecies) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void curve25519_setupDefaults(java.nio.ByteBuffer cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey curve25519_generateKey(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer curve25519_new();

    public native void curve25519_close(java.nio.ByteBuffer cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId curve25519_algId(java.nio.ByteBuffer cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo curve25519_produceAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void curve25519_restoreAlgInfo(java.nio.ByteBuffer cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey curve25519_generateEphemeralKey(java.nio.ByteBuffer cCtx, Key key) throws FoundationException;

    /*
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native PublicKey curve25519_importPublicKey(java.nio.ByteBuffer cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey curve25519_exportPublicKey(java.nio.ByteBuffer cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native PrivateKey curve25519_importPrivateKey(java.nio.ByteBuffer cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey curve25519_exportPrivateKey(java.nio.ByteBuffer cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean curve25519_canEncrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int curve25519_encryptedLen(java.nio.ByteBuffer cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] curve25519_encrypt(java.nio.ByteBuffer cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean curve25519_canDecrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int curve25519_decryptedLen(java.nio.ByteBuffer cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] curve25519_decrypt(java.nio.ByteBuffer cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public native byte[] curve25519_computeSharedKey(java.nio.ByteBuffer cCtx, PublicKey publicKey, PrivateKey privateKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public native int curve25519_sharedKeyLen(java.nio.ByteBuffer cCtx, Key key);

    public native java.nio.ByteBuffer simpleAlgInfo_new();

    public native void simpleAlgInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer simpleAlgInfo_new(AlgId algId);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId simpleAlgInfo_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return hash algorithm information.
    */
    public native AlgInfo hashBasedAlgInfo_hashAlgInfo(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer hashBasedAlgInfo_new();

    public native void hashBasedAlgInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer hashBasedAlgInfo_new(AlgId algId, AlgInfo hashAlgInfo);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId hashBasedAlgInfo_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return IV.
    */
    public native byte[] cipherAlgInfo_nonce(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer cipherAlgInfo_new();

    public native void cipherAlgInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer cipherAlgInfo_new(AlgId algId, byte[] nonce);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId cipherAlgInfo_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return hash algorithm information.
    */
    public native AlgInfo saltedKdfAlgInfo_hashAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Return KDF salt.
    */
    public native byte[] saltedKdfAlgInfo_salt(java.nio.ByteBuffer cCtx);

    /*
    * Return KDF iteration count.
    * Note, can be 0 if KDF does not need the iteration count.
    */
    public native int saltedKdfAlgInfo_iterationCount(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer saltedKdfAlgInfo_new();

    public native void saltedKdfAlgInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer saltedKdfAlgInfo_new(AlgId algId, AlgInfo hashAlgInfo, byte[] salt, int iterationCount);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId saltedKdfAlgInfo_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return KDF algorithm information.
    */
    public native AlgInfo pbeAlgInfo_kdfAlgInfo(java.nio.ByteBuffer cCtx);

    /*
    * Return cipher algorithm information.
    */
    public native AlgInfo pbeAlgInfo_cipherAlgInfo(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer pbeAlgInfo_new();

    public native void pbeAlgInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer pbeAlgInfo_new(AlgId algId, AlgInfo kdfAlgInfo, AlgInfo cipherAlgInfo);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId pbeAlgInfo_algId(java.nio.ByteBuffer cCtx);

    /*
    * Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}.
    */
    public native OidId eccAlgInfo_keyId(java.nio.ByteBuffer cCtx);

    /*
    * Return EC domain group identificator.
    */
    public native OidId eccAlgInfo_domainId(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer eccAlgInfo_new();

    public native void eccAlgInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer eccAlgInfo_new(AlgId algId, OidId keyId, OidId domainId);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId eccAlgInfo_algId(java.nio.ByteBuffer cCtx);

    public native void algInfoDerSerializer_setAsn1Writer(java.nio.ByteBuffer cCtx, Asn1Writer asn1Writer);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void algInfoDerSerializer_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Serialize by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int algInfoDerSerializer_serializeInplace(java.nio.ByteBuffer cCtx, AlgInfo algInfo);

    public native java.nio.ByteBuffer algInfoDerSerializer_new();

    public native void algInfoDerSerializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Return buffer size enough to hold serialized algorithm.
    */
    public native int algInfoDerSerializer_serializedLen(java.nio.ByteBuffer cCtx, AlgInfo algInfo);

    /*
    * Serialize algorithm info to buffer class.
    */
    public native byte[] algInfoDerSerializer_serialize(java.nio.ByteBuffer cCtx, AlgInfo algInfo);

    public native void algInfoDerDeserializer_setAsn1Reader(java.nio.ByteBuffer cCtx, Asn1Reader asn1Reader);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void algInfoDerDeserializer_setupDefaults(java.nio.ByteBuffer cCtx);

    /*
    * Deserialize by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native AlgInfo algInfoDerDeserializer_deserializeInplace(java.nio.ByteBuffer cCtx) throws FoundationException;

    public native java.nio.ByteBuffer algInfoDerDeserializer_new();

    public native void algInfoDerDeserializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Deserialize algorithm from the data.
    */
    public native AlgInfo algInfoDerDeserializer_deserialize(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;

    public native void messageInfoDerSerializer_setAsn1Reader(java.nio.ByteBuffer cCtx, Asn1Reader asn1Reader) throws FoundationException;

    public native void messageInfoDerSerializer_setAsn1Writer(java.nio.ByteBuffer cCtx, Asn1Writer asn1Writer) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void messageInfoDerSerializer_setupDefaults(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer messageInfoDerSerializer_new();

    public native void messageInfoDerSerializer_close(java.nio.ByteBuffer cCtx);

    /*
    * Return buffer size enough to hold serialized message info.
    */
    public native int messageInfoDerSerializer_serializedLen(java.nio.ByteBuffer cCtx, MessageInfo messageInfo);

    /*
    * Serialize class "message info".
    */
    public native byte[] messageInfoDerSerializer_serialize(java.nio.ByteBuffer cCtx, MessageInfo messageInfo);

    /*
    * Read message info prefix from the given data, and if it is valid,
    * return a length of bytes of the whole message info.
    *
    * Zero returned if length can not be determined from the given data,
    * and this means that there is no message info at the data beginning.
    */
    public native int messageInfoDerSerializer_readPrefix(java.nio.ByteBuffer cCtx, byte[] data);

    /*
    * Deserialize class "message info".
    */
    public native MessageInfo messageInfoDerSerializer_deserialize(java.nio.ByteBuffer cCtx, byte[] data) throws FoundationException;
}

