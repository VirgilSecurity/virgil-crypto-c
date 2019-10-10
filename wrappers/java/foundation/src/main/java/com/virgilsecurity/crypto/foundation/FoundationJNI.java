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
        NativeUtils.load("vscf_foundation");
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

    public native long messageInfo_new();

    public native void messageInfo_close(long cCtx);

    /*
    * Return information about algorithm that was used for the data encryption.
    */
    public native AlgInfo messageInfo_dataEncryptionAlgInfo(long cCtx);

    /*
    * Return list with a "key recipient info" elements.
    */
    public native KeyRecipientInfoList messageInfo_keyRecipientInfoList(long cCtx);

    /*
    * Return list with a "password recipient info" elements.
    */
    public native PasswordRecipientInfoList messageInfo_passwordRecipientInfoList(long cCtx);

    /*
    * Return true if message info contains at least one custom param.
    */
    public native boolean messageInfo_hasCustomParams(long cCtx);

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    * If custom params object was not set then new empty object is created.
    */
    public native MessageInfoCustomParams messageInfo_customParams(long cCtx);

    /*
    * Return true if cipher kdf alg info exists.
    */
    public native boolean messageInfo_hasCipherKdfAlgInfo(long cCtx);

    /*
    * Return cipher kdf alg info.
    */
    public native AlgInfo messageInfo_cipherKdfAlgInfo(long cCtx);

    /*
    * Return true if footer info exists.
    */
    public native boolean messageInfo_hasFooterInfo(long cCtx);

    /*
    * Return footer info.
    */
    public native FooterInfo messageInfo_footerInfo(long cCtx);

    /*
    * Remove all infos.
    */
    public native void messageInfo_clear(long cCtx);

    public native long keyRecipientInfo_new();

    public native void keyRecipientInfo_close(long cCtx);

    public native long keyRecipientInfo_new(byte[] recipientId, AlgInfo keyEncryptionAlgorithm, byte[] encryptedKey);

    /*
    * Return recipient identifier.
    */
    public native byte[] keyRecipientInfo_recipientId(long cCtx);

    /*
    * Return algorithm information that was used for encryption
    * a data encryption key.
    */
    public native AlgInfo keyRecipientInfo_keyEncryptionAlgorithm(long cCtx);

    /*
    * Return an encrypted data encryption key.
    */
    public native byte[] keyRecipientInfo_encryptedKey(long cCtx);

    public native long keyRecipientInfoList_new();

    public native void keyRecipientInfoList_close(long cCtx);

    /*
    * Return true if given list has item.
    */
    public native boolean keyRecipientInfoList_hasItem(long cCtx);

    /*
    * Return list item.
    */
    public native KeyRecipientInfo keyRecipientInfoList_item(long cCtx);

    /*
    * Return true if list has next item.
    */
    public native boolean keyRecipientInfoList_hasNext(long cCtx);

    /*
    * Return next list node if exists, or NULL otherwise.
    */
    public native KeyRecipientInfoList keyRecipientInfoList_next(long cCtx);

    /*
    * Return true if list has previous item.
    */
    public native boolean keyRecipientInfoList_hasPrev(long cCtx);

    /*
    * Return previous list node if exists, or NULL otherwise.
    */
    public native KeyRecipientInfoList keyRecipientInfoList_prev(long cCtx);

    /*
    * Remove all items.
    */
    public native void keyRecipientInfoList_clear(long cCtx);

    public native long passwordRecipientInfo_new();

    public native void passwordRecipientInfo_close(long cCtx);

    public native long passwordRecipientInfo_new(AlgInfo keyEncryptionAlgorithm, byte[] encryptedKey);

    /*
    * Return algorithm information that was used for encryption
    * a data encryption key.
    */
    public native AlgInfo passwordRecipientInfo_keyEncryptionAlgorithm(long cCtx);

    /*
    * Return an encrypted data encryption key.
    */
    public native byte[] passwordRecipientInfo_encryptedKey(long cCtx);

    public native long passwordRecipientInfoList_new();

    public native void passwordRecipientInfoList_close(long cCtx);

    /*
    * Return true if given list has item.
    */
    public native boolean passwordRecipientInfoList_hasItem(long cCtx);

    /*
    * Return list item.
    */
    public native PasswordRecipientInfo passwordRecipientInfoList_item(long cCtx);

    /*
    * Return true if list has next item.
    */
    public native boolean passwordRecipientInfoList_hasNext(long cCtx);

    /*
    * Return next list node if exists, or NULL otherwise.
    */
    public native PasswordRecipientInfoList passwordRecipientInfoList_next(long cCtx);

    /*
    * Return true if list has previous item.
    */
    public native boolean passwordRecipientInfoList_hasPrev(long cCtx);

    /*
    * Return previous list node if exists, or NULL otherwise.
    */
    public native PasswordRecipientInfoList passwordRecipientInfoList_prev(long cCtx);

    /*
    * Remove all items.
    */
    public native void passwordRecipientInfoList_clear(long cCtx);

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

    public native long ecies_new();

    public native void ecies_close(long cCtx);

    public native void ecies_setRandom(long cCtx, Random random);

    public native void ecies_setCipher(long cCtx, Cipher cipher);

    public native void ecies_setMac(long cCtx, Mac mac);

    public native void ecies_setKdf(long cCtx, Kdf kdf);

    /*
    * Set ephemeral key that used for data encryption.
    * Public and ephemeral keys should belong to the same curve.
    * This dependency is optional.
    */
    public native void ecies_setEphemeralKey(long cCtx, PrivateKey ephemeralKey);

    /*
    * Set weak reference to the key algorithm.
    * Key algorithm MUST support shared key computation as well.
    */
    public native void ecies_setKeyAlg(long cCtx, KeyAlg keyAlg);

    /*
    * Release weak reference to the key algorithm.
    */
    public native void ecies_releaseKeyAlg(long cCtx);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ecies_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies
    * except random.
    */
    public native void ecies_setupDefaultsNoRandom(long cCtx);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ecies_encryptedLen(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] ecies_encrypt(long cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ecies_decryptedLen(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ecies_decrypt(long cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    public native long recipientCipher_new();

    public native void recipientCipher_close(long cCtx);

    public native void recipientCipher_setRandom(long cCtx, Random random);

    public native void recipientCipher_setEncryptionCipher(long cCtx, Cipher encryptionCipher);

    public native void recipientCipher_setSignerHash(long cCtx, Hash signerHash);

    /*
    * Return true if a key recipient with a given id has been added.
    * Note, operation has O(N) time complexity.
    */
    public native boolean recipientCipher_hasKeyRecipient(long cCtx, byte[] recipientId);

    /*
    * Add recipient defined with id and public key.
    */
    public native void recipientCipher_addKeyRecipient(long cCtx, byte[] recipientId, PublicKey publicKey);

    /*
    * Remove all recipients.
    */
    public native void recipientCipher_clearRecipients(long cCtx);

    /*
    * Add identifier and private key to sign initial plain text.
    * Return error if the private key can not sign.
    */
    public native void recipientCipher_addSigner(long cCtx, byte[] signerId, PrivateKey privateKey) throws FoundationException;

    /*
    * Remove all signers.
    */
    public native void recipientCipher_clearSigners(long cCtx);

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    */
    public native MessageInfoCustomParams recipientCipher_customParams(long cCtx);

    /*
    * Start encryption process.
    */
    public native void recipientCipher_startEncryption(long cCtx) throws FoundationException;

    /*
    * Start encryption process with known plain text size.
    *
    * Precondition: At least one signer should be added.
    * Note, store message info footer as well.
    */
    public native void recipientCipher_startSignedEncryption(long cCtx, int dataSize) throws FoundationException;

    /*
    * Return buffer length required to hold message info returned by the
    * "pack message info" method.
    * Precondition: all recipients and custom parameters should be set.
    */
    public native int recipientCipher_messageInfoLen(long cCtx);

    /*
    * Return serialized message info to the buffer.
    *
    * Precondition: this method should be called after "start encryption".
    * Precondition: this method should be called before "finish encryption".
    *
    * Note, store message info to use it for decryption process,
    * or place it at the encrypted data beginning (embedding).
    *
    * Return message info - recipients public information,
    * algorithm information, etc.
    */
    public native byte[] recipientCipher_packMessageInfo(long cCtx);

    /*
    * Return buffer length required to hold output of the method
    * "process encryption" and method "finish" during encryption.
    */
    public native int recipientCipher_encryptionOutLen(long cCtx, int dataLen);

    /*
    * Process encryption of a new portion of data.
    */
    public native byte[] recipientCipher_processEncryption(long cCtx, byte[] data) throws FoundationException;

    /*
    * Accomplish encryption.
    */
    public native byte[] recipientCipher_finishEncryption(long cCtx) throws FoundationException;

    /*
    * Initiate decryption process with a recipient private key.
    * Message Info can be empty if it was embedded to encrypted data.
    */
    public native void recipientCipher_startDecryptionWithKey(long cCtx, byte[] recipientId, PrivateKey privateKey, byte[] messageInfo) throws FoundationException;

    /*
    * Initiate decryption process with a recipient private key.
    * Message Info can be empty if it was embedded to encrypted data.
    * Message Info footer can be empty if it was embedded to encrypted data.
    * If footer was embedded, method "start decryption with key" can be used.
    */
    public native void recipientCipher_startVerifiedDecryptionWithKey(long cCtx, byte[] recipientId, PrivateKey privateKey, byte[] messageInfo, byte[] messageInfoFooter) throws FoundationException;

    /*
    * Return buffer length required to hold output of the method
    * "process decryption" and method "finish" during decryption.
    */
    public native int recipientCipher_decryptionOutLen(long cCtx, int dataLen);

    /*
    * Process with a new portion of data.
    * Return error if data can not be encrypted or decrypted.
    */
    public native byte[] recipientCipher_processDecryption(long cCtx, byte[] data) throws FoundationException;

    /*
    * Accomplish decryption.
    */
    public native byte[] recipientCipher_finishDecryption(long cCtx) throws FoundationException;

    /*
    * Return true if data was signed by a sender.
    *
    * Precondition: this method should be called after "finish decryption".
    */
    public native boolean recipientCipher_isDataSigned(long cCtx);

    /*
    * Return information about signers that sign data.
    *
    * Precondition: this method should be called after "finish decryption".
    * Precondition: method "is data signed" returns true.
    */
    public native SignerInfoList recipientCipher_signerInfos(long cCtx);

    /*
    * Verify given cipher info.
    */
    public native boolean recipientCipher_verifySignerInfo(long cCtx, SignerInfo signerInfo, PublicKey publicKey);

    /*
    * Return buffer length required to hold message footer returned by the
    * "pack message footer" method.
    *
    * Precondition: this method should be called after "finish encryption".
    */
    public native int recipientCipher_messageInfoFooterLen(long cCtx);

    /*
    * Return serialized message info footer to the buffer.
    *
    * Precondition: this method should be called after "finish encryption".
    *
    * Note, store message info to use it for verified decryption process,
    * or place it at the encrypted data ending (embedding).
    *
    * Return message info footer - signers public information, etc.
    */
    public native byte[] recipientCipher_packMessageInfoFooter(long cCtx) throws FoundationException;

    public native long messageInfoCustomParams_new();

    public native void messageInfoCustomParams_close(long cCtx);

    /*
    * Add custom parameter with integer value.
    */
    public native void messageInfoCustomParams_addInt(long cCtx, byte[] key, int value);

    /*
    * Add custom parameter with UTF8 string value.
    */
    public native void messageInfoCustomParams_addString(long cCtx, byte[] key, byte[] value);

    /*
    * Add custom parameter with octet string value.
    */
    public native void messageInfoCustomParams_addData(long cCtx, byte[] key, byte[] value);

    /*
    * Remove all parameters.
    */
    public native void messageInfoCustomParams_clear(long cCtx);

    /*
    * Return custom parameter with integer value.
    */
    public native int messageInfoCustomParams_findInt(long cCtx, byte[] key) throws FoundationException;

    /*
    * Return custom parameter with UTF8 string value.
    */
    public native byte[] messageInfoCustomParams_findString(long cCtx, byte[] key) throws FoundationException;

    /*
    * Return custom parameter with octet string value.
    */
    public native byte[] messageInfoCustomParams_findData(long cCtx, byte[] key) throws FoundationException;

    /*
    * Return true if at least one param exists.
    */
    public native boolean messageInfoCustomParams_hasParams(long cCtx);

    public native long keyProvider_new();

    public native void keyProvider_close(long cCtx);

    public native void keyProvider_setRandom(long cCtx, Random random);

    public native void keyProvider_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void keyProvider_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Setup parameters that is used during RSA key generation.
    */
    public native void keyProvider_setRsaParams(long cCtx, int bitlen);

    /*
    * Generate new private key from the given id.
    */
    public native PrivateKey keyProvider_generatePrivateKey(long cCtx, AlgId algId) throws FoundationException;

    /*
    * Import private key from the PKCS#8 format.
    */
    public native PrivateKey keyProvider_importPrivateKey(long cCtx, byte[] keyData) throws FoundationException;

    /*
    * Import public key from the PKCS#8 format.
    */
    public native PublicKey keyProvider_importPublicKey(long cCtx, byte[] keyData) throws FoundationException;

    /*
    * Calculate buffer size enough to hold exported public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int keyProvider_exportedPublicKeyLen(long cCtx, PublicKey publicKey);

    /*
    * Export given public key to the PKCS#8 DER format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] keyProvider_exportPublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold exported private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int keyProvider_exportedPrivateKeyLen(long cCtx, PrivateKey privateKey);

    /*
    * Export given private key to the PKCS#8 or SEC1 DER format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] keyProvider_exportPrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

    public native long signer_new();

    public native void signer_close(long cCtx);

    public native void signer_setHash(long cCtx, Hash hash);

    public native void signer_setRandom(long cCtx, Random random);

    /*
    * Start a processing a new signature.
    */
    public native void signer_reset(long cCtx);

    /*
    * Add given data to the signed data.
    */
    public native void signer_appendData(long cCtx, byte[] data);

    /*
    * Return length of the signature.
    */
    public native int signer_signatureLen(long cCtx, PrivateKey privateKey);

    /*
    * Accomplish signing and return signature.
    */
    public native byte[] signer_sign(long cCtx, PrivateKey privateKey) throws FoundationException;

    public native long verifier_new();

    public native void verifier_close(long cCtx);

    /*
    * Start verifying a signature.
    */
    public native void verifier_reset(long cCtx, byte[] signature) throws FoundationException;

    /*
    * Add given data to the signed data.
    */
    public native void verifier_appendData(long cCtx, byte[] data);

    /*
    * Verify accumulated data.
    */
    public native boolean verifier_verify(long cCtx, PublicKey publicKey);

    public native long brainkeyClient_new();

    public native void brainkeyClient_close(long cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void brainkeyClient_setRandom(long cCtx, Random random);

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void brainkeyClient_setOperationRandom(long cCtx, Random operationRandom);

    public native void brainkeyClient_setupDefaults(long cCtx) throws FoundationException;

    public native BrainkeyClientBlindResult brainkeyClient_blind(long cCtx, byte[] password) throws FoundationException;

    public native byte[] brainkeyClient_deblind(long cCtx, byte[] password, byte[] hardenedPoint, byte[] deblindFactor, byte[] keyName) throws FoundationException;

    public native long brainkeyServer_new();

    public native void brainkeyServer_close(long cCtx);

    /*
    * Random used for key generation, proofs, etc.
    */
    public native void brainkeyServer_setRandom(long cCtx, Random random);

    /*
    * Random used for crypto operations to make them const-time
    */
    public native void brainkeyServer_setOperationRandom(long cCtx, Random operationRandom);

    public native void brainkeyServer_setupDefaults(long cCtx) throws FoundationException;

    public native byte[] brainkeyServer_generateIdentitySecret(long cCtx) throws FoundationException;

    public native byte[] brainkeyServer_harden(long cCtx, byte[] identitySecret, byte[] blindedPoint) throws FoundationException;

    public native long groupSessionMessage_new();

    public native void groupSessionMessage_close(long cCtx);

    /*
    * Returns message type.
    */
    public native GroupMsgType groupSessionMessage_getType(long cCtx);

    /*
    * Returns session id.
    * This method should be called only for group info type.
    */
    public native byte[] groupSessionMessage_getSessionId(long cCtx);

    /*
    * Returns message epoch.
    */
    public native long groupSessionMessage_getEpoch(long cCtx);

    /*
    * Buffer len to serialize this class.
    */
    public native int groupSessionMessage_serializeLen(long cCtx);

    /*
    * Serializes instance.
    */
    public native byte[] groupSessionMessage_serialize(long cCtx);

    /*
    * Deserializes instance.
    */
    public native GroupSessionMessage groupSessionMessage_deserialize(byte[] input) throws FoundationException;

    public native long groupSessionTicket_new();

    public native void groupSessionTicket_close(long cCtx);

    /*
    * Random used to generate keys
    */
    public native void groupSessionTicket_setRng(long cCtx, Random rng);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void groupSessionTicket_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Set this ticket to start new group session.
    */
    public native void groupSessionTicket_setupTicketAsNew(long cCtx, byte[] sessionId) throws FoundationException;

    /*
    * Returns message that should be sent to all participants using secure channel.
    */
    public native GroupSessionMessage groupSessionTicket_getTicketMessage(long cCtx);

    public native long groupSession_new();

    public native void groupSession_close(long cCtx);

    /*
    * Random
    */
    public native void groupSession_setRng(long cCtx, Random rng) throws FoundationException;

    /*
    * Returns current epoch.
    */
    public native long groupSession_getCurrentEpoch(long cCtx);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void groupSession_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Returns session id.
    */
    public native byte[] groupSession_getSessionId(long cCtx);

    /*
    * Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
    * Epoch message should be encrypted and signed by trusted group chat member (admin).
    */
    public native void groupSession_addEpoch(long cCtx, GroupSessionMessage message) throws FoundationException;

    /*
    * Encrypts data
    */
    public native GroupSessionMessage groupSession_encrypt(long cCtx, byte[] plainText, PrivateKey privateKey) throws FoundationException;

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public native int groupSession_decryptLen(long cCtx, GroupSessionMessage message);

    /*
    * Decrypts message
    */
    public native byte[] groupSession_decrypt(long cCtx, GroupSessionMessage message, PublicKey publicKey) throws FoundationException;

    /*
    * Creates ticket with new key for removing participants or proactive to rotate encryption key.
    */
    public native GroupSessionTicket groupSession_createGroupTicket(long cCtx) throws FoundationException;

    public native long messageInfoEditor_new();

    public native void messageInfoEditor_close(long cCtx);

    public native void messageInfoEditor_setRandom(long cCtx, Random random);

    /*
    * Set dependencies to it's defaults.
    */
    public native void messageInfoEditor_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Unpack serialized message info.
    *
    * Note that recipients can only be removed but not added.
    * Note, use "unlock" method to be able to add new recipients as well.
    */
    public native void messageInfoEditor_unpack(long cCtx, byte[] messageInfoData) throws FoundationException;

    /*
    * Decrypt encryption key this allows adding new recipients.
    */
    public native void messageInfoEditor_unlock(long cCtx, byte[] ownerRecipientId, PrivateKey ownerPrivateKey) throws FoundationException;

    /*
    * Add recipient defined with id and public key.
    */
    public native void messageInfoEditor_addKeyRecipient(long cCtx, byte[] recipientId, PublicKey publicKey) throws FoundationException;

    /*
    * Remove recipient with a given id.
    * Return false if recipient with given id was not found.
    */
    public native boolean messageInfoEditor_removeKeyRecipient(long cCtx, byte[] recipientId);

    /*
    * Remove all existent recipients.
    */
    public native void messageInfoEditor_removeAll(long cCtx);

    /*
    * Return length of serialized message info.
    * Actual length can be obtained right after applying changes.
    */
    public native int messageInfoEditor_packedLen(long cCtx);

    /*
    * Return serialized message info.
    * Precondition: this method can be called after "apply".
    */
    public native byte[] messageInfoEditor_pack(long cCtx);

    public native long signerInfo_new();

    public native void signerInfo_close(long cCtx);

    /*
    * Return signer identifier.
    */
    public native byte[] signerInfo_signerId(long cCtx);

    /*
    * Return algorithm information that was used for data signing.
    */
    public native AlgInfo signerInfo_signerAlgInfo(long cCtx);

    /*
    * Return data signature.
    */
    public native byte[] signerInfo_signature(long cCtx);

    public native long signerInfoList_new();

    public native void signerInfoList_close(long cCtx);

    /*
    * Return true if given list has item.
    */
    public native boolean signerInfoList_hasItem(long cCtx);

    /*
    * Return list item.
    */
    public native SignerInfo signerInfoList_item(long cCtx);

    /*
    * Return true if list has next item.
    */
    public native boolean signerInfoList_hasNext(long cCtx);

    /*
    * Return next list node if exists, or NULL otherwise.
    */
    public native SignerInfoList signerInfoList_next(long cCtx);

    /*
    * Return true if list has previous item.
    */
    public native boolean signerInfoList_hasPrev(long cCtx);

    /*
    * Return previous list node if exists, or NULL otherwise.
    */
    public native SignerInfoList signerInfoList_prev(long cCtx);

    /*
    * Remove all items.
    */
    public native void signerInfoList_clear(long cCtx);

    public native long messageInfoFooter_new();

    public native void messageInfoFooter_close(long cCtx);

    /*
    * Return true if at least one signer info presents.
    */
    public native boolean messageInfoFooter_hasSignerInfos(long cCtx);

    /*
    * Return list with a "signer info" elements.
    */
    public native SignerInfoList messageInfoFooter_signerInfos(long cCtx);

    /*
    * Return information about algorithm that was used for data hashing.
    */
    public native AlgInfo messageInfoFooter_signerHashAlgInfo(long cCtx);

    /*
    * Return plain text digest that was used to produce signature.
    */
    public native byte[] messageInfoFooter_signerDigest(long cCtx);

    public native long signedDataInfo_new();

    public native void signedDataInfo_close(long cCtx);

    /*
    * Set information about algorithm that was used to produce data digest.
    */
    public native void signedDataInfo_setHashAlgInfo(long cCtx, AlgInfo hashAlgInfo);

    /*
    * Return information about algorithm that was used to produce data digest.
    */
    public native AlgInfo signedDataInfo_hashAlgInfo(long cCtx);

    public native long footerInfo_new();

    public native void footerInfo_close(long cCtx);

    /*
    * Retrun true if signed data info present.
    */
    public native boolean footerInfo_hasSignedDataInfo(long cCtx);

    /*
    * Return signed data info.
    */
    public native SignedDataInfo footerInfo_signedDataInfo(long cCtx);

    /*
    * Set data size.
    */
    public native void footerInfo_setDataSize(long cCtx, int dataSize);

    /*
    * Return data size.
    */
    public native int footerInfo_dataSize(long cCtx);

    public native long sha224_new();

    public native void sha224_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha224_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha224_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha224_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha224_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha224_start(long cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha224_update(long cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha224_finish(long cCtx);

    public native long sha256_new();

    public native void sha256_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha256_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha256_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha256_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha256_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha256_start(long cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha256_update(long cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha256_finish(long cCtx);

    public native long sha384_new();

    public native void sha384_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha384_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha384_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha384_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha384_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha384_start(long cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha384_update(long cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha384_finish(long cCtx);

    public native long sha512_new();

    public native void sha512_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId sha512_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo sha512_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void sha512_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Calculate hash over given data.
    */
    public native byte[] sha512_hash(byte[] data);

    /*
    * Start a new hashing.
    */
    public native void sha512_start(long cCtx);

    /*
    * Add given data to the hash.
    */
    public native void sha512_update(long cCtx, byte[] data);

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public native byte[] sha512_finish(long cCtx);

    public native long aes256Gcm_new();

    public native void aes256Gcm_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId aes256Gcm_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo aes256Gcm_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void aes256Gcm_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Encrypt given data.
    */
    public native byte[] aes256Gcm_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int aes256Gcm_encryptedLen(long cCtx, int dataLen);

    /*
    * Precise length calculation of encrypted data.
    */
    public native int aes256Gcm_preciseEncryptedLen(long cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] aes256Gcm_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int aes256Gcm_decryptedLen(long cCtx, int dataLen);

    /*
    * Setup IV or nonce.
    */
    public native void aes256Gcm_setNonce(long cCtx, byte[] nonce);

    /*
    * Set cipher encryption / decryption key.
    */
    public native void aes256Gcm_setKey(long cCtx, byte[] key);

    /*
    * Start sequential encryption.
    */
    public native void aes256Gcm_startEncryption(long cCtx);

    /*
    * Start sequential decryption.
    */
    public native void aes256Gcm_startDecryption(long cCtx);

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public native byte[] aes256Gcm_update(long cCtx, byte[] data);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Gcm_outLen(long cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Gcm_encryptedOutLen(long cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Gcm_decryptedOutLen(long cCtx, int dataLen);

    /*
    * Accomplish encryption or decryption process.
    */
    public native byte[] aes256Gcm_finish(long cCtx) throws FoundationException;

    /*
    * Encrypt given data.
    * If 'tag' is not given, then it will written to the 'enc'.
    */
    public native AuthEncryptAuthEncryptResult aes256Gcm_authEncrypt(long cCtx, byte[] data, byte[] authData) throws FoundationException;

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
    */
    public native int aes256Gcm_authEncryptedLen(long cCtx, int dataLen);

    /*
    * Decrypt given data.
    * If 'tag' is not given, then it will be taken from the 'enc'.
    */
    public native byte[] aes256Gcm_authDecrypt(long cCtx, byte[] data, byte[] authData, byte[] tag) throws FoundationException;

    /*
    * Calculate required buffer length to hold the authenticated decrypted data.
    */
    public native int aes256Gcm_authDecryptedLen(long cCtx, int dataLen);

    /*
    * Set additional data for for AEAD ciphers.
    */
    public native void aes256Gcm_setAuthData(long cCtx, byte[] authData);

    /*
    * Accomplish an authenticated encryption and place tag separately.
    *
    * Note, if authentication tag should be added to an encrypted data,
    * method "finish" can be used.
    */
    public native CipherAuthFinishAuthEncryptionResult aes256Gcm_finishAuthEncryption(long cCtx) throws FoundationException;

    /*
    * Accomplish an authenticated decryption with explicitly given tag.
    *
    * Note, if authentication tag is a part of an encrypted data then,
    * method "finish" can be used for simplicity.
    */
    public native byte[] aes256Gcm_finishAuthDecryption(long cCtx, byte[] tag) throws FoundationException;

    public native long aes256Cbc_new();

    public native void aes256Cbc_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId aes256Cbc_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo aes256Cbc_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void aes256Cbc_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Encrypt given data.
    */
    public native byte[] aes256Cbc_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int aes256Cbc_encryptedLen(long cCtx, int dataLen);

    /*
    * Precise length calculation of encrypted data.
    */
    public native int aes256Cbc_preciseEncryptedLen(long cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] aes256Cbc_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int aes256Cbc_decryptedLen(long cCtx, int dataLen);

    /*
    * Setup IV or nonce.
    */
    public native void aes256Cbc_setNonce(long cCtx, byte[] nonce);

    /*
    * Set cipher encryption / decryption key.
    */
    public native void aes256Cbc_setKey(long cCtx, byte[] key);

    /*
    * Start sequential encryption.
    */
    public native void aes256Cbc_startEncryption(long cCtx);

    /*
    * Start sequential decryption.
    */
    public native void aes256Cbc_startDecryption(long cCtx);

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public native byte[] aes256Cbc_update(long cCtx, byte[] data);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Cbc_outLen(long cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Cbc_encryptedOutLen(long cCtx, int dataLen);

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public native int aes256Cbc_decryptedOutLen(long cCtx, int dataLen);

    /*
    * Accomplish encryption or decryption process.
    */
    public native byte[] aes256Cbc_finish(long cCtx) throws FoundationException;

    public native long asn1rd_new();

    public native void asn1rd_close(long cCtx);

    /*
    * Reset all internal states and prepare to new ASN.1 reading operations.
    */
    public native void asn1rd_reset(long cCtx, byte[] data);

    /*
    * Return length in bytes how many bytes are left for reading.
    */
    public native int asn1rd_leftLen(long cCtx);

    /*
    * Return true if status is not "success".
    */
    public native boolean asn1rd_hasError(long cCtx);

    /*
    * Return error code.
    */
    public native void asn1rd_status(long cCtx) throws FoundationException;

    /*
    * Get tag of the current ASN.1 element.
    */
    public native int asn1rd_getTag(long cCtx);

    /*
    * Get length of the current ASN.1 element.
    */
    public native int asn1rd_getLen(long cCtx);

    /*
    * Get length of the current ASN.1 element with tag and length itself.
    */
    public native int asn1rd_getDataLen(long cCtx);

    /*
    * Read ASN.1 type: TAG.
    * Return element length.
    */
    public native int asn1rd_readTag(long cCtx, int tag);

    /*
    * Read ASN.1 type: context-specific TAG.
    * Return element length.
    * Return 0 if current position do not points to the requested tag.
    */
    public native int asn1rd_readContextTag(long cCtx, int tag);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native int asn1rd_readInt(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native byte asn1rd_readInt8(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native short asn1rd_readInt16(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native int asn1rd_readInt32(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readInt64(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readUint(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native short asn1rd_readUint8(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native int asn1rd_readUint16(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readUint32(long cCtx);

    /*
    * Read ASN.1 type: INTEGER.
    */
    public native long asn1rd_readUint64(long cCtx);

    /*
    * Read ASN.1 type: BOOLEAN.
    */
    public native boolean asn1rd_readBool(long cCtx);

    /*
    * Read ASN.1 type: NULL.
    */
    public native void asn1rd_readNull(long cCtx);

    /*
    * Read ASN.1 type: NULL, only if it exists.
    * Note, this method is safe to call even no more data is left for reading.
    */
    public native void asn1rd_readNullOptional(long cCtx);

    /*
    * Read ASN.1 type: OCTET STRING.
    */
    public native byte[] asn1rd_readOctetStr(long cCtx);

    /*
    * Read ASN.1 type: BIT STRING.
    */
    public native byte[] asn1rd_readBitstringAsOctetStr(long cCtx);

    /*
    * Read ASN.1 type: UTF8String.
    */
    public native byte[] asn1rd_readUtf8Str(long cCtx);

    /*
    * Read ASN.1 type: OID.
    */
    public native byte[] asn1rd_readOid(long cCtx);

    /*
    * Read raw data of given length.
    */
    public native byte[] asn1rd_readData(long cCtx, int len);

    /*
    * Read ASN.1 type: SEQUENCE.
    * Return element length.
    */
    public native int asn1rd_readSequence(long cCtx);

    /*
    * Read ASN.1 type: SET.
    * Return element length.
    */
    public native int asn1rd_readSet(long cCtx);

    public native long asn1wr_new();

    public native void asn1wr_close(long cCtx);

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
    */
    public native void asn1wr_reset(long cCtx, byte[] out, int outLen);

    /*
    * Finalize writing and forbid further operations.
    *
    * Note, that ASN.1 structure is always written to the buffer end, and
    * if argument "do not adjust" is false, then data is moved to the
    * beginning, otherwise - data is left at the buffer end.
    *
    * Returns length of the written bytes.
    */
    public native int asn1wr_finish(long cCtx, boolean doNotAdjust);

    /*
    * Returns pointer to the inner buffer.
    */
    public native byte asn1wr_bytes(long cCtx);

    /*
    * Returns total inner buffer length.
    */
    public native int asn1wr_len(long cCtx);

    /*
    * Returns how many bytes were already written to the ASN.1 structure.
    */
    public native int asn1wr_writtenLen(long cCtx);

    /*
    * Returns how many bytes are available for writing.
    */
    public native int asn1wr_unwrittenLen(long cCtx);

    /*
    * Return true if status is not "success".
    */
    public native boolean asn1wr_hasError(long cCtx);

    /*
    * Return error code.
    */
    public native void asn1wr_status(long cCtx) throws FoundationException;

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
    */
    public native byte asn1wr_reserve(long cCtx, int len);

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
    */
    public native int asn1wr_writeTag(long cCtx, int tag);

    /*
    * Write context-specific ASN.1 tag.
    * Return count of written bytes.
    */
    public native int asn1wr_writeContextTag(long cCtx, int tag, int len);

    /*
    * Write length of the following data.
    * Return count of written bytes.
    */
    public native int asn1wr_writeLen(long cCtx, int len);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt(long cCtx, int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt8(long cCtx, byte value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt16(long cCtx, short value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt32(long cCtx, int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeInt64(long cCtx, long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint(long cCtx, long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint8(long cCtx, short value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint16(long cCtx, int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint32(long cCtx, long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUint64(long cCtx, long value);

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
    */
    public native int asn1wr_writeBool(long cCtx, boolean value);

    /*
    * Write ASN.1 type: NULL.
    */
    public native int asn1wr_writeNull(long cCtx);

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
    */
    public native int asn1wr_writeOctetStr(long cCtx, byte[] value);

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
    */
    public native int asn1wr_writeOctetStrAsBitstring(long cCtx, byte[] value);

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
    */
    public native int asn1wr_writeData(long cCtx, byte[] data);

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
    */
    public native int asn1wr_writeUtf8Str(long cCtx, byte[] value);

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
    */
    public native int asn1wr_writeOid(long cCtx, byte[] value);

    /*
    * Mark previously written data of given length as ASN.1 type: SEQUENCE.
    * Return count of written bytes.
    */
    public native int asn1wr_writeSequence(long cCtx, int len);

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    */
    public native int asn1wr_writeSet(long cCtx, int len);

    /*
    * Return public key exponent.
    */
    public native int rsaPublicKey_keyExponent(long cCtx);

    public native long rsaPublicKey_new();

    public native void rsaPublicKey_close(long cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rsaPublicKey_algId(long cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rsaPublicKey_algInfo(long cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rsaPublicKey_len(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rsaPublicKey_bitlen(long cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rsaPublicKey_isValid(long cCtx);

    public native long rsaPrivateKey_new();

    public native void rsaPrivateKey_close(long cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rsaPrivateKey_algId(long cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rsaPrivateKey_algInfo(long cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rsaPrivateKey_len(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rsaPrivateKey_bitlen(long cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rsaPrivateKey_isValid(long cCtx);

    /*
    * Extract public key from the private key.
    */
    public native PublicKey rsaPrivateKey_extractPublicKey(long cCtx);

    public native void rsa_setRandom(long cCtx, Random random);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void rsa_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey rsa_generateKey(long cCtx, int bitlen) throws FoundationException;

    public native long rsa_new();

    public native void rsa_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId rsa_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo rsa_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void rsa_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey rsa_generateEphemeralKey(long cCtx, Key key) throws FoundationException;

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
    public native PublicKey rsa_importPublicKey(long cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey rsa_exportPublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

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
    public native PrivateKey rsa_importPrivateKey(long cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey rsa_exportPrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean rsa_canEncrypt(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int rsa_encryptedLen(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] rsa_encrypt(long cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean rsa_canDecrypt(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int rsa_decryptedLen(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] rsa_decrypt(long cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean rsa_canSign(long cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int rsa_signatureLen(long cCtx, PrivateKey privateKey);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] rsa_signHash(long cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean rsa_canVerify(long cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean rsa_verifyHash(long cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    public native long eccPublicKey_new();

    public native void eccPublicKey_close(long cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId eccPublicKey_algId(long cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo eccPublicKey_algInfo(long cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int eccPublicKey_len(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int eccPublicKey_bitlen(long cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean eccPublicKey_isValid(long cCtx);

    public native long eccPrivateKey_new();

    public native void eccPrivateKey_close(long cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId eccPrivateKey_algId(long cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo eccPrivateKey_algInfo(long cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int eccPrivateKey_len(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int eccPrivateKey_bitlen(long cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean eccPrivateKey_isValid(long cCtx);

    /*
    * Extract public key from the private key.
    */
    public native PublicKey eccPrivateKey_extractPublicKey(long cCtx);

    public native void ecc_setRandom(long cCtx, Random random);

    public native void ecc_setEcies(long cCtx, Ecies ecies) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ecc_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Supported algorithm ids:
    * - secp256r1.
    *
    * Note, this operation might be slow.
    */
    public native PrivateKey ecc_generateKey(long cCtx, AlgId algId) throws FoundationException;

    public native long ecc_new();

    public native void ecc_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ecc_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo ecc_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void ecc_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey ecc_generateEphemeralKey(long cCtx, Key key) throws FoundationException;

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
    public native PublicKey ecc_importPublicKey(long cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey ecc_exportPublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

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
    public native PrivateKey ecc_importPrivateKey(long cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey ecc_exportPrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean ecc_canEncrypt(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ecc_encryptedLen(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] ecc_encrypt(long cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean ecc_canDecrypt(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ecc_decryptedLen(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ecc_decrypt(long cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean ecc_canSign(long cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int ecc_signatureLen(long cCtx, PrivateKey privateKey);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] ecc_signHash(long cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean ecc_canVerify(long cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean ecc_verifyHash(long cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public native byte[] ecc_computeSharedKey(long cCtx, PublicKey publicKey, PrivateKey privateKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public native int ecc_sharedKeyLen(long cCtx, Key key);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void entropyAccumulator_setupDefaults(long cCtx);

    /*
    * Add given entropy source to the accumulator.
    * Threshold defines minimum number of bytes that must be gathered
    * from the source during accumulation.
    */
    public native void entropyAccumulator_addSource(long cCtx, EntropySource source, int threshold);

    public native long entropyAccumulator_new();

    public native void entropyAccumulator_close(long cCtx);

    /*
    * Defines that implemented source is strong.
    */
    public native boolean entropyAccumulator_isStrong(long cCtx);

    /*
    * Gather entropy of the requested length.
    */
    public native byte[] entropyAccumulator_gather(long cCtx, int len) throws FoundationException;

    public native void ctrDrbg_setEntropySource(long cCtx, EntropySource entropySource) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ctrDrbg_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Force entropy to be gathered at the beginning of every call to
    * the random() method.
    * Note, use this if your entropy source has sufficient throughput.
    */
    public native void ctrDrbg_enablePredictionResistance(long cCtx);

    /*
    * Sets the reseed interval.
    * Default value is reseed interval.
    */
    public native void ctrDrbg_setReseedInterval(long cCtx, int interval);

    /*
    * Sets the amount of entropy grabbed on each seed or reseed.
    * The default value is entropy len.
    */
    public native void ctrDrbg_setEntropyLen(long cCtx, int len);

    public native long ctrDrbg_new();

    public native void ctrDrbg_close(long cCtx);

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public native byte[] ctrDrbg_random(long cCtx, int dataLen) throws FoundationException;

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public native void ctrDrbg_reseed(long cCtx) throws FoundationException;

    public native void hmac_setHash(long cCtx, Hash hash);

    public native long hmac_new();

    public native void hmac_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId hmac_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo hmac_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void hmac_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Size of the digest (mac output) in bytes.
    */
    public native int hmac_digestLen(long cCtx);

    /*
    * Calculate MAC over given data.
    */
    public native byte[] hmac_mac(long cCtx, byte[] key, byte[] data);

    /*
    * Start a new MAC.
    */
    public native void hmac_start(long cCtx, byte[] key);

    /*
    * Add given data to the MAC.
    */
    public native void hmac_update(long cCtx, byte[] data);

    /*
    * Accomplish MAC and return it's result (a message digest).
    */
    public native byte[] hmac_finish(long cCtx);

    /*
    * Prepare to authenticate a new message with the same key
    * as the previous MAC operation.
    */
    public native void hmac_reset(long cCtx);

    public native void hkdf_setHash(long cCtx, Hash hash);

    public native long hkdf_new();

    public native void hkdf_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId hkdf_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo hkdf_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void hkdf_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] hkdf_derive(long cCtx, byte[] data, int keyLen);

    /*
    * Prepare algorithm to derive new key.
    */
    public native void hkdf_reset(long cCtx, byte[] salt, int iterationCount);

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    public native void hkdf_setInfo(long cCtx, byte[] info);

    public native void kdf1_setHash(long cCtx, Hash hash);

    public native long kdf1_new();

    public native void kdf1_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId kdf1_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo kdf1_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void kdf1_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] kdf1_derive(long cCtx, byte[] data, int keyLen);

    public native void kdf2_setHash(long cCtx, Hash hash);

    public native long kdf2_new();

    public native void kdf2_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId kdf2_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo kdf2_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void kdf2_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] kdf2_derive(long cCtx, byte[] data, int keyLen);

    /*
    * Configure random number generator to generate sequence filled with given byte.
    */
    public native void fakeRandom_setupSourceByte(long cCtx, byte byteSource);

    /*
    * Configure random number generator to generate random sequence from given data.
    * Note, that given data is used as circular source.
    */
    public native void fakeRandom_setupSourceData(long cCtx, byte[] dataSource);

    public native long fakeRandom_new();

    public native void fakeRandom_close(long cCtx);

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public native byte[] fakeRandom_random(long cCtx, int dataLen) throws FoundationException;

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public native void fakeRandom_reseed(long cCtx) throws FoundationException;

    /*
    * Defines that implemented source is strong.
    */
    public native boolean fakeRandom_isStrong(long cCtx);

    /*
    * Gather entropy of the requested length.
    */
    public native byte[] fakeRandom_gather(long cCtx, int len) throws FoundationException;

    public native void pkcs5Pbkdf2_setHmac(long cCtx, Mac hmac);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void pkcs5Pbkdf2_setupDefaults(long cCtx);

    public native long pkcs5Pbkdf2_new();

    public native void pkcs5Pbkdf2_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId pkcs5Pbkdf2_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo pkcs5Pbkdf2_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void pkcs5Pbkdf2_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Derive key of the requested length from the given data.
    */
    public native byte[] pkcs5Pbkdf2_derive(long cCtx, byte[] data, int keyLen);

    /*
    * Prepare algorithm to derive new key.
    */
    public native void pkcs5Pbkdf2_reset(long cCtx, byte[] salt, int iterationCount);

    /*
    * Setup application specific information (optional).
    * Can be empty.
    */
    public native void pkcs5Pbkdf2_setInfo(long cCtx, byte[] info);

    public native void pkcs5Pbes2_setKdf(long cCtx, SaltedKdf kdf);

    public native void pkcs5Pbes2_setCipher(long cCtx, Cipher cipher);

    /*
    * Configure cipher with a new password.
    */
    public native void pkcs5Pbes2_reset(long cCtx, byte[] pwd);

    public native long pkcs5Pbes2_new();

    public native void pkcs5Pbes2_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId pkcs5Pbes2_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo pkcs5Pbes2_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void pkcs5Pbes2_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Encrypt given data.
    */
    public native byte[] pkcs5Pbes2_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int pkcs5Pbes2_encryptedLen(long cCtx, int dataLen);

    /*
    * Precise length calculation of encrypted data.
    */
    public native int pkcs5Pbes2_preciseEncryptedLen(long cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] pkcs5Pbes2_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int pkcs5Pbes2_decryptedLen(long cCtx, int dataLen);

    /*
    * Set a new seed as an entropy source.
    */
    public native void seedEntropySource_resetSeed(long cCtx, byte[] seed);

    public native long seedEntropySource_new();

    public native void seedEntropySource_close(long cCtx);

    /*
    * Defines that implemented source is strong.
    */
    public native boolean seedEntropySource_isStrong(long cCtx);

    /*
    * Gather entropy of the requested length.
    */
    public native byte[] seedEntropySource_gather(long cCtx, int len) throws FoundationException;

    /*
    * Set a new key material.
    */
    public native void keyMaterialRng_resetKeyMaterial(long cCtx, byte[] keyMaterial);

    public native long keyMaterialRng_new();

    public native void keyMaterialRng_close(long cCtx);

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public native byte[] keyMaterialRng_random(long cCtx, int dataLen) throws FoundationException;

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public native void keyMaterialRng_reseed(long cCtx) throws FoundationException;

    /*
    * Return key data.
    */
    public native byte[] rawPublicKey_data(long cCtx);

    public native long rawPublicKey_new();

    public native void rawPublicKey_close(long cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rawPublicKey_algId(long cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rawPublicKey_algInfo(long cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rawPublicKey_len(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rawPublicKey_bitlen(long cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rawPublicKey_isValid(long cCtx);

    /*
    * Return key data.
    */
    public native byte[] rawPrivateKey_data(long cCtx);

    /*
    * Return true if private key contains public key.
    */
    public native boolean rawPrivateKey_hasPublicKey(long cCtx);

    /*
    * Setup public key related to the private key.
    */
    public native void rawPrivateKey_setPublicKey(long cCtx, RawPublicKey rawPublicKey);

    /*
    * Return public key related to the private key.
    */
    public native RawPublicKey rawPrivateKey_getPublicKey(long cCtx);

    public native long rawPrivateKey_new();

    public native void rawPrivateKey_close(long cCtx);

    /*
    * Algorithm identifier the key belongs to.
    */
    public native AlgId rawPrivateKey_algId(long cCtx);

    /*
    * Return algorithm information that can be used for serialization.
    */
    public native AlgInfo rawPrivateKey_algInfo(long cCtx);

    /*
    * Length of the key in bytes.
    */
    public native int rawPrivateKey_len(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rawPrivateKey_bitlen(long cCtx);

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public native boolean rawPrivateKey_isValid(long cCtx);

    /*
    * Extract public key from the private key.
    */
    public native PublicKey rawPrivateKey_extractPublicKey(long cCtx);

    public native void pkcs8Serializer_setAsn1Writer(long cCtx, Asn1Writer asn1Writer);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void pkcs8Serializer_setupDefaults(long cCtx);

    /*
    * Serialize Public Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int pkcs8Serializer_serializePublicKeyInplace(long cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int pkcs8Serializer_serializePrivateKeyInplace(long cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native long pkcs8Serializer_new();

    public native void pkcs8Serializer_close(long cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int pkcs8Serializer_serializedPublicKeyLen(long cCtx, RawPublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] pkcs8Serializer_serializePublicKey(long cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int pkcs8Serializer_serializedPrivateKeyLen(long cCtx, RawPrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] pkcs8Serializer_serializePrivateKey(long cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native void sec1Serializer_setAsn1Writer(long cCtx, Asn1Writer asn1Writer) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void sec1Serializer_setupDefaults(long cCtx);

    /*
    * Serialize Public Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int sec1Serializer_serializePublicKeyInplace(long cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int sec1Serializer_serializePrivateKeyInplace(long cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native long sec1Serializer_new();

    public native void sec1Serializer_close(long cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int sec1Serializer_serializedPublicKeyLen(long cCtx, RawPublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] sec1Serializer_serializePublicKey(long cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int sec1Serializer_serializedPrivateKeyLen(long cCtx, RawPrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] sec1Serializer_serializePrivateKey(long cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native void keyAsn1Serializer_setAsn1Writer(long cCtx, Asn1Writer asn1Writer) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void keyAsn1Serializer_setupDefaults(long cCtx);

    /*
    * Serialize Public Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int keyAsn1Serializer_serializePublicKeyInplace(long cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int keyAsn1Serializer_serializePrivateKeyInplace(long cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native long keyAsn1Serializer_new();

    public native void keyAsn1Serializer_close(long cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int keyAsn1Serializer_serializedPublicKeyLen(long cCtx, RawPublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] keyAsn1Serializer_serializePublicKey(long cCtx, RawPublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int keyAsn1Serializer_serializedPrivateKeyLen(long cCtx, RawPrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] keyAsn1Serializer_serializePrivateKey(long cCtx, RawPrivateKey privateKey) throws FoundationException;

    public native void keyAsn1Deserializer_setAsn1Reader(long cCtx, Asn1Reader asn1Reader) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void keyAsn1Deserializer_setupDefaults(long cCtx);

    /*
    * Deserialize Public Key by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native RawPublicKey keyAsn1Deserializer_deserializePublicKeyInplace(long cCtx) throws FoundationException;

    /*
    * Deserialize Private Key by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native RawPrivateKey keyAsn1Deserializer_deserializePrivateKeyInplace(long cCtx) throws FoundationException;

    public native long keyAsn1Deserializer_new();

    public native void keyAsn1Deserializer_close(long cCtx);

    /*
    * Deserialize given public key as an interchangeable format to the object.
    */
    public native RawPublicKey keyAsn1Deserializer_deserializePublicKey(long cCtx, byte[] publicKeyData) throws FoundationException;

    /*
    * Deserialize given private key as an interchangeable format to the object.
    */
    public native RawPrivateKey keyAsn1Deserializer_deserializePrivateKey(long cCtx, byte[] privateKeyData) throws FoundationException;

    public native void ed25519_setRandom(long cCtx, Random random);

    public native void ed25519_setEcies(long cCtx, Ecies ecies) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ed25519_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey ed25519_generateKey(long cCtx) throws FoundationException;

    public native long ed25519_new();

    public native void ed25519_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ed25519_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo ed25519_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void ed25519_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey ed25519_generateEphemeralKey(long cCtx, Key key) throws FoundationException;

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
    public native PublicKey ed25519_importPublicKey(long cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey ed25519_exportPublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

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
    public native PrivateKey ed25519_importPrivateKey(long cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey ed25519_exportPrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean ed25519_canEncrypt(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ed25519_encryptedLen(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] ed25519_encrypt(long cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean ed25519_canDecrypt(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ed25519_decryptedLen(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ed25519_decrypt(long cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean ed25519_canSign(long cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int ed25519_signatureLen(long cCtx, PrivateKey privateKey);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] ed25519_signHash(long cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean ed25519_canVerify(long cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean ed25519_verifyHash(long cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public native byte[] ed25519_computeSharedKey(long cCtx, PublicKey publicKey, PrivateKey privateKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public native int ed25519_sharedKeyLen(long cCtx, Key key);

    public native void curve25519_setRandom(long cCtx, Random random);

    public native void curve25519_setEcies(long cCtx, Ecies ecies) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void curve25519_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey curve25519_generateKey(long cCtx) throws FoundationException;

    public native long curve25519_new();

    public native void curve25519_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId curve25519_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo curve25519_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void curve25519_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey curve25519_generateEphemeralKey(long cCtx, Key key) throws FoundationException;

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
    public native PublicKey curve25519_importPublicKey(long cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey curve25519_exportPublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

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
    public native PrivateKey curve25519_importPrivateKey(long cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey curve25519_exportPrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public native boolean curve25519_canEncrypt(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int curve25519_encryptedLen(long cCtx, PublicKey publicKey, int dataLen);

    /*
    * Encrypt data with a given public key.
    */
    public native byte[] curve25519_encrypt(long cCtx, PublicKey publicKey, byte[] data) throws FoundationException;

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public native boolean curve25519_canDecrypt(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int curve25519_decryptedLen(long cCtx, PrivateKey privateKey, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] curve25519_decrypt(long cCtx, PrivateKey privateKey, byte[] data) throws FoundationException;

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public native byte[] curve25519_computeSharedKey(long cCtx, PublicKey publicKey, PrivateKey privateKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public native int curve25519_sharedKeyLen(long cCtx, Key key);

    public native void falcon_setRandom(long cCtx, Random random);

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public native PrivateKey falcon_generateKey(long cCtx) throws FoundationException;

    public native long falcon_new();

    public native void falcon_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId falcon_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo falcon_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void falcon_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public native PrivateKey falcon_generateEphemeralKey(long cCtx, Key key) throws FoundationException;

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
    public native PublicKey falcon_importPublicKey(long cCtx, RawPublicKey rawKey) throws FoundationException;

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native RawPublicKey falcon_exportPublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

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
    public native PrivateKey falcon_importPrivateKey(long cCtx, RawPrivateKey rawKey) throws FoundationException;

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native RawPrivateKey falcon_exportPrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public native boolean falcon_canSign(long cCtx, PrivateKey privateKey);

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public native int falcon_signatureLen(long cCtx, PrivateKey privateKey);

    /*
    * Sign data digest with a given private key.
    */
    public native byte[] falcon_signHash(long cCtx, PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException;

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public native boolean falcon_canVerify(long cCtx, PublicKey publicKey);

    /*
    * Verify data digest with a given public key and signature.
    */
    public native boolean falcon_verifyHash(long cCtx, PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature);

    public native long simpleAlgInfo_new();

    public native void simpleAlgInfo_close(long cCtx);

    public native long simpleAlgInfo_new(AlgId algId);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId simpleAlgInfo_algId(long cCtx);

    /*
    * Return hash algorithm information.
    */
    public native AlgInfo hashBasedAlgInfo_hashAlgInfo(long cCtx);

    public native long hashBasedAlgInfo_new();

    public native void hashBasedAlgInfo_close(long cCtx);

    public native long hashBasedAlgInfo_new(AlgId algId, AlgInfo hashAlgInfo);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId hashBasedAlgInfo_algId(long cCtx);

    /*
    * Return IV.
    */
    public native byte[] cipherAlgInfo_nonce(long cCtx);

    public native long cipherAlgInfo_new();

    public native void cipherAlgInfo_close(long cCtx);

    public native long cipherAlgInfo_new(AlgId algId, byte[] nonce);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId cipherAlgInfo_algId(long cCtx);

    /*
    * Return hash algorithm information.
    */
    public native AlgInfo saltedKdfAlgInfo_hashAlgInfo(long cCtx);

    /*
    * Return KDF salt.
    */
    public native byte[] saltedKdfAlgInfo_salt(long cCtx);

    /*
    * Return KDF iteration count.
    * Note, can be 0 if KDF does not need the iteration count.
    */
    public native int saltedKdfAlgInfo_iterationCount(long cCtx);

    public native long saltedKdfAlgInfo_new();

    public native void saltedKdfAlgInfo_close(long cCtx);

    public native long saltedKdfAlgInfo_new(AlgId algId, AlgInfo hashAlgInfo, byte[] salt, int iterationCount);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId saltedKdfAlgInfo_algId(long cCtx);

    /*
    * Return KDF algorithm information.
    */
    public native AlgInfo pbeAlgInfo_kdfAlgInfo(long cCtx);

    /*
    * Return cipher algorithm information.
    */
    public native AlgInfo pbeAlgInfo_cipherAlgInfo(long cCtx);

    public native long pbeAlgInfo_new();

    public native void pbeAlgInfo_close(long cCtx);

    public native long pbeAlgInfo_new(AlgId algId, AlgInfo kdfAlgInfo, AlgInfo cipherAlgInfo);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId pbeAlgInfo_algId(long cCtx);

    /*
    * Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}.
    */
    public native OidId eccAlgInfo_keyId(long cCtx);

    /*
    * Return EC domain group identificator.
    */
    public native OidId eccAlgInfo_domainId(long cCtx);

    public native long eccAlgInfo_new();

    public native void eccAlgInfo_close(long cCtx);

    public native long eccAlgInfo_new(AlgId algId, OidId keyId, OidId domainId);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId eccAlgInfo_algId(long cCtx);

    public native void algInfoDerSerializer_setAsn1Writer(long cCtx, Asn1Writer asn1Writer);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void algInfoDerSerializer_setupDefaults(long cCtx);

    /*
    * Serialize by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int algInfoDerSerializer_serializeInplace(long cCtx, AlgInfo algInfo);

    public native long algInfoDerSerializer_new();

    public native void algInfoDerSerializer_close(long cCtx);

    /*
    * Return buffer size enough to hold serialized algorithm.
    */
    public native int algInfoDerSerializer_serializedLen(long cCtx, AlgInfo algInfo);

    /*
    * Serialize algorithm info to buffer class.
    */
    public native byte[] algInfoDerSerializer_serialize(long cCtx, AlgInfo algInfo);

    public native void algInfoDerDeserializer_setAsn1Reader(long cCtx, Asn1Reader asn1Reader);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void algInfoDerDeserializer_setupDefaults(long cCtx);

    /*
    * Deserialize by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native AlgInfo algInfoDerDeserializer_deserializeInplace(long cCtx) throws FoundationException;

    public native long algInfoDerDeserializer_new();

    public native void algInfoDerDeserializer_close(long cCtx);

    /*
    * Deserialize algorithm from the data.
    */
    public native AlgInfo algInfoDerDeserializer_deserialize(long cCtx, byte[] data) throws FoundationException;

    public native void messageInfoDerSerializer_setAsn1Reader(long cCtx, Asn1Reader asn1Reader) throws FoundationException;

    public native void messageInfoDerSerializer_setAsn1Writer(long cCtx, Asn1Writer asn1Writer) throws FoundationException;

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void messageInfoDerSerializer_setupDefaults(long cCtx);

    public native long messageInfoDerSerializer_new();

    public native void messageInfoDerSerializer_close(long cCtx);

    /*
    * Return buffer size enough to hold serialized message info.
    */
    public native int messageInfoDerSerializer_serializedLen(long cCtx, MessageInfo messageInfo);

    /*
    * Serialize class "message info".
    */
    public native byte[] messageInfoDerSerializer_serialize(long cCtx, MessageInfo messageInfo);

    /*
    * Read message info prefix from the given data, and if it is valid,
    * return a length of bytes of the whole message info.
    *
    * Zero returned if length can not be determined from the given data,
    * and this means that there is no message info at the data beginning.
    */
    public native int messageInfoDerSerializer_readPrefix(long cCtx, byte[] data);

    /*
    * Deserialize class "message info".
    */
    public native MessageInfo messageInfoDerSerializer_deserialize(long cCtx, byte[] data) throws FoundationException;

    /*
    * Return buffer size enough to hold serialized message info footer.
    */
    public native int messageInfoDerSerializer_serializedFooterLen(long cCtx, MessageInfoFooter messageInfoFooter);

    /*
    * Serialize class "message info footer".
    */
    public native byte[] messageInfoDerSerializer_serializeFooter(long cCtx, MessageInfoFooter messageInfoFooter);

    /*
    * Deserialize class "message info footer".
    */
    public native MessageInfoFooter messageInfoDerSerializer_deserializeFooter(long cCtx, byte[] data) throws FoundationException;
}

