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

    public native long rawKey_new();

    public native void rawKey_close(long cCtx);

    public native long rawKey_new(AlgId algId, byte[] rawKeyData);

    /*
    * Returns asymmetric algorithm type that raw key belongs to.
    */
    public native AlgId rawKey_algId(long cCtx);

    /*
    * Return raw key data.
    */
    public native byte[] rawKey_data(long cCtx);

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
    * Add recipient that is defined by Public Key.
    */
    public native void messageInfo_addKeyRecipient(long cCtx, KeyRecipientInfo keyRecipient);

    /*
    * Add recipient that is defined by password.
    */
    public native void messageInfo_addPasswordRecipient(long cCtx, PasswordRecipientInfo passwordRecipient);

    /*
    * Set information about algorithm that was used for data encryption.
    */
    public native void messageInfo_setDataEncryptionAlgInfo(long cCtx, AlgInfo dataEncryptionAlgInfo);

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
    * Setup custom params.
    */
    public native void messageInfo_setCustomParams(long cCtx, MessageInfoCustomParams customParams);

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    * If custom params object was not set then new empty object is created.
    */
    public native MessageInfoCustomParams messageInfo_customParams(long cCtx);

    /*
    * Remove all recipients.
    */
    public native void messageInfo_clearRecipients(long cCtx);

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
    * Add new item to the list.
    * Note, ownership is transfered.
    */
    public native void keyRecipientInfoList_add(long cCtx, KeyRecipientInfo keyRecipientInfo);

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
    * Add new item to the list.
    * Note, ownership is transfered.
    */
    public native void passwordRecipientInfoList_add(long cCtx, PasswordRecipientInfo passwordRecipientInfo);

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
    * Create algorithm that implements "public key" interface.
    */
    public native PublicKey algFactory_createPublicKeyFromRawKey(RawKey rawKey) throws FoundationException;

    /*
    * Create algorithm that implements "private key" interface.
    */
    public native PrivateKey algFactory_createPrivateKeyFromRawKey(RawKey rawKey) throws FoundationException;

    public native long recipientCipher_new();

    public native void recipientCipher_close(long cCtx);

    public native void recipientCipher_setRandom(long cCtx, Random random);

    public native void recipientCipher_setEncryptionCipher(long cCtx, Cipher encryptionCipher);

    /*
    * Add recipient defined with id and public key.
    */
    public native void recipientCipher_addKeyRecipient(long cCtx, byte[] recipientId, PublicKey publicKey);

    /*
    * Remove all recipients.
    */
    public native void recipientCipher_clearRecipients(long cCtx);

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    */
    public native MessageInfoCustomParams recipientCipher_customParams(long cCtx);

    /*
    * Return buffer length required to hold message info returned by the
    * "start encryption" method.
    * Precondition: all recipients and custom parameters should be set.
    */
    public native int recipientCipher_messageInfoLen(long cCtx);

    /*
    * Start encryption process.
    */
    public native void recipientCipher_startEncryption(long cCtx) throws FoundationException;

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
    * Message info can be empty if it was embedded to encrypted data.
    */
    public native void recipientCipher_startDecryptionWithKey(long cCtx, byte[] recipientId, PrivateKey privateKey, byte[] messageInfo) throws FoundationException;

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

    public native long listKeyValueNode_new();

    public native void listKeyValueNode_close(long cCtx);

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

    /*
    * Start a processing a new signature.
    */
    public native void signer_reset(long cCtx);

    /*
    * Add given data to the signed data.
    */
    public native void signer_update(long cCtx, byte[] data);

    /*
    * Return length of the signature.
    */
    public native int signer_signatureLen(long cCtx, SignHash privateKey);

    /*
    * Accomplish signing and return signature.
    */
    public native byte[] signer_sign(long cCtx, SignHash privateKey) throws FoundationException;

    public native long verifier_new();

    public native void verifier_close(long cCtx);

    /*
    * Start verifying a signature.
    */
    public native void verifier_reset(long cCtx, byte[] signature) throws FoundationException;

    /*
    * Add given data to the signed data.
    */
    public native void verifier_update(long cCtx, byte[] data);

    /*
    * Verify accumulated data.
    */
    public native boolean verifier_verify(long cCtx, VerifyHash publicKey);

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
    * Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    * Return element length.
    */
    public native int asn1rd_readSequence(long cCtx);

    /*
    * Read ASN.1 type: CONSTRUCTED | SET.
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
    * Mark previously written data of given length as ASN.1 type: SQUENCE.
    * Return count of written bytes.
    */
    public native int asn1wr_writeSequence(long cCtx, int len);

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    */
    public native int asn1wr_writeSet(long cCtx, int len);

    public native void rsaPublicKey_setHash(long cCtx, Hash hash);

    public native void rsaPublicKey_setRandom(long cCtx, Random random);

    public native void rsaPublicKey_setAsn1rd(long cCtx, Asn1Reader asn1rd);

    public native void rsaPublicKey_setAsn1wr(long cCtx, Asn1Writer asn1wr);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void rsaPublicKey_setupDefaults(long cCtx) throws FoundationException;

    public native long rsaPublicKey_new();

    public native void rsaPublicKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId rsaPublicKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo rsaPublicKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void rsaPublicKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int rsaPublicKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rsaPublicKey_keyBitlen(long cCtx);

    /*
    * Encrypt given data.
    */
    public native byte[] rsaPublicKey_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int rsaPublicKey_encryptedLen(long cCtx, int dataLen);

    /*
    * Verify data with given public key and signature.
    */
    public native boolean rsaPublicKey_verifyHash(long cCtx, byte[] hashDigest, AlgId hashId, byte[] signature);

    /*
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native byte[] rsaPublicKey_exportPublicKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported public key.
    */
    public native int rsaPublicKey_exportedPublicKeyLen(long cCtx);

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native void rsaPublicKey_importPublicKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    */
    public native PrivateKey rsaPublicKey_generateEphemeralKey(long cCtx) throws FoundationException;

    public native void rsaPrivateKey_setRandom(long cCtx, Random random);

    public native void rsaPrivateKey_setAsn1rd(long cCtx, Asn1Reader asn1rd);

    public native void rsaPrivateKey_setAsn1wr(long cCtx, Asn1Writer asn1wr);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void rsaPrivateKey_setupDefaults(long cCtx) throws FoundationException;

    /*
    * Setup key length in bits that is used for key generation.
    */
    public native void rsaPrivateKey_setKeygenParams(long cCtx, int bitlen);

    public native long rsaPrivateKey_new();

    public native void rsaPrivateKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId rsaPrivateKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo rsaPrivateKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void rsaPrivateKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int rsaPrivateKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int rsaPrivateKey_keyBitlen(long cCtx);

    /*
    * Generate new private or secret key.
    * Note, this operation can be slow.
    */
    public native void rsaPrivateKey_generateKey(long cCtx) throws FoundationException;

    /*
    * Decrypt given data.
    */
    public native byte[] rsaPrivateKey_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int rsaPrivateKey_decryptedLen(long cCtx, int dataLen);

    /*
    * Return length in bytes required to hold signature.
    */
    public native int rsaPrivateKey_signatureLen(long cCtx);

    /*
    * Sign data given private key.
    */
    public native byte[] rsaPrivateKey_signHash(long cCtx, byte[] hashDigest, AlgId hashId) throws FoundationException;

    /*
    * Extract public part of the key.
    */
    public native PublicKey rsaPrivateKey_extractPublicKey(long cCtx);

    /*
    * Export private key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native byte[] rsaPrivateKey_exportPrivateKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported private key.
    */
    public native int rsaPrivateKey_exportedPrivateKeyLen(long cCtx);

    /*
    * Import private key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native void rsaPrivateKey_importPrivateKey(long cCtx, byte[] data) throws FoundationException;

    public native void secp256r1PublicKey_setRandom(long cCtx, Random random);

    public native void secp256r1PublicKey_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void secp256r1PublicKey_setupDefaults(long cCtx) throws FoundationException;

    public native long secp256r1PublicKey_new();

    public native void secp256r1PublicKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId secp256r1PublicKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo secp256r1PublicKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void secp256r1PublicKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int secp256r1PublicKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int secp256r1PublicKey_keyBitlen(long cCtx);

    /*
    * Encrypt given data.
    */
    public native byte[] secp256r1PublicKey_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int secp256r1PublicKey_encryptedLen(long cCtx, int dataLen);

    /*
    * Verify data with given public key and signature.
    */
    public native boolean secp256r1PublicKey_verifyHash(long cCtx, byte[] hashDigest, AlgId hashId, byte[] signature);

    /*
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native byte[] secp256r1PublicKey_exportPublicKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported public key.
    */
    public native int secp256r1PublicKey_exportedPublicKeyLen(long cCtx);

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native void secp256r1PublicKey_importPublicKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    */
    public native PrivateKey secp256r1PublicKey_generateEphemeralKey(long cCtx) throws FoundationException;

    public native void secp256r1PrivateKey_setRandom(long cCtx, Random random);

    public native void secp256r1PrivateKey_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void secp256r1PrivateKey_setupDefaults(long cCtx) throws FoundationException;

    public native long secp256r1PrivateKey_new();

    public native void secp256r1PrivateKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId secp256r1PrivateKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo secp256r1PrivateKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void secp256r1PrivateKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int secp256r1PrivateKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int secp256r1PrivateKey_keyBitlen(long cCtx);

    /*
    * Generate new private or secret key.
    * Note, this operation can be slow.
    */
    public native void secp256r1PrivateKey_generateKey(long cCtx) throws FoundationException;

    /*
    * Decrypt given data.
    */
    public native byte[] secp256r1PrivateKey_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int secp256r1PrivateKey_decryptedLen(long cCtx, int dataLen);

    /*
    * Return length in bytes required to hold signature.
    */
    public native int secp256r1PrivateKey_signatureLen(long cCtx);

    /*
    * Sign data given private key.
    */
    public native byte[] secp256r1PrivateKey_signHash(long cCtx, byte[] hashDigest, AlgId hashId) throws FoundationException;

    /*
    * Extract public part of the key.
    */
    public native PublicKey secp256r1PrivateKey_extractPublicKey(long cCtx);

    /*
    * Export private key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native byte[] secp256r1PrivateKey_exportPrivateKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported private key.
    */
    public native int secp256r1PrivateKey_exportedPrivateKeyLen(long cCtx);

    /*
    * Import private key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native void secp256r1PrivateKey_importPrivateKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, shared key can be used only for symmetric cryptography.
    */
    public native byte[] secp256r1PrivateKey_computeSharedKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    */
    public native int secp256r1PrivateKey_sharedKeyLen(long cCtx);

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
    */
    public native byte[] ctrDrbg_random(long cCtx, int dataLen) throws FoundationException;

    /*
    * Retreive new seed data from the entropy sources.
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
    */
    public native byte[] fakeRandom_random(long cCtx, int dataLen) throws FoundationException;

    /*
    * Retreive new seed data from the entropy sources.
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
    */
    public native byte[] keyMaterialRng_random(long cCtx, int dataLen) throws FoundationException;

    /*
    * Retreive new seed data from the entropy sources.
    */
    public native void keyMaterialRng_reseed(long cCtx) throws FoundationException;

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
    public native int pkcs8Serializer_serializePublicKeyInplace(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int pkcs8Serializer_serializePrivateKeyInplace(long cCtx, PrivateKey privateKey) throws FoundationException;

    public native long pkcs8Serializer_new();

    public native void pkcs8Serializer_close(long cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int pkcs8Serializer_serializedPublicKeyLen(long cCtx, PublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] pkcs8Serializer_serializePublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int pkcs8Serializer_serializedPrivateKeyLen(long cCtx, PrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] pkcs8Serializer_serializePrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

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
    public native int sec1Serializer_serializePublicKeyInplace(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int sec1Serializer_serializePrivateKeyInplace(long cCtx, PrivateKey privateKey) throws FoundationException;

    public native long sec1Serializer_new();

    public native void sec1Serializer_close(long cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int sec1Serializer_serializedPublicKeyLen(long cCtx, PublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] sec1Serializer_serializePublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int sec1Serializer_serializedPrivateKeyLen(long cCtx, PrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] sec1Serializer_serializePrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

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
    public native int keyAsn1Serializer_serializePublicKeyInplace(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Serialize Private Key by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public native int keyAsn1Serializer_serializePrivateKeyInplace(long cCtx, PrivateKey privateKey) throws FoundationException;

    public native long keyAsn1Serializer_new();

    public native void keyAsn1Serializer_close(long cCtx);

    /*
    * Calculate buffer size enough to hold serialized public key.
    *
    * Precondition: public key must be exportable.
    */
    public native int keyAsn1Serializer_serializedPublicKeyLen(long cCtx, PublicKey publicKey);

    /*
    * Serialize given public key to an interchangeable format.
    *
    * Precondition: public key must be exportable.
    */
    public native byte[] keyAsn1Serializer_serializePublicKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Calculate buffer size enough to hold serialized private key.
    *
    * Precondition: private key must be exportable.
    */
    public native int keyAsn1Serializer_serializedPrivateKeyLen(long cCtx, PrivateKey privateKey);

    /*
    * Serialize given private key to an interchangeable format.
    *
    * Precondition: private key must be exportable.
    */
    public native byte[] keyAsn1Serializer_serializePrivateKey(long cCtx, PrivateKey privateKey) throws FoundationException;

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
    public native RawKey keyAsn1Deserializer_deserializePublicKeyInplace(long cCtx) throws FoundationException;

    /*
    * Deserialize Private Key by using internal ASN.1 reader.
    * Note, that caller code is responsible to reset ASN.1 reader with
    * an input buffer.
    */
    public native RawKey keyAsn1Deserializer_deserializePrivateKeyInplace(long cCtx) throws FoundationException;

    public native long keyAsn1Deserializer_new();

    public native void keyAsn1Deserializer_close(long cCtx);

    /*
    * Deserialize given public key as an interchangeable format to the object.
    */
    public native RawKey keyAsn1Deserializer_deserializePublicKey(long cCtx, byte[] publicKeyData) throws FoundationException;

    /*
    * Deserialize given private key as an interchangeable format to the object.
    */
    public native RawKey keyAsn1Deserializer_deserializePrivateKey(long cCtx, byte[] privateKeyData) throws FoundationException;

    public native void ed25519PublicKey_setRandom(long cCtx, Random random);

    public native void ed25519PublicKey_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ed25519PublicKey_setupDefaults(long cCtx) throws FoundationException;

    public native long ed25519PublicKey_new();

    public native void ed25519PublicKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ed25519PublicKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo ed25519PublicKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void ed25519PublicKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int ed25519PublicKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int ed25519PublicKey_keyBitlen(long cCtx);

    /*
    * Encrypt given data.
    */
    public native byte[] ed25519PublicKey_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ed25519PublicKey_encryptedLen(long cCtx, int dataLen);

    /*
    * Verify data with given public key and signature.
    */
    public native boolean ed25519PublicKey_verifyHash(long cCtx, byte[] hashDigest, AlgId hashId, byte[] signature);

    /*
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native byte[] ed25519PublicKey_exportPublicKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported public key.
    */
    public native int ed25519PublicKey_exportedPublicKeyLen(long cCtx);

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native void ed25519PublicKey_importPublicKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    */
    public native PrivateKey ed25519PublicKey_generateEphemeralKey(long cCtx) throws FoundationException;

    public native void ed25519PrivateKey_setRandom(long cCtx, Random random);

    public native void ed25519PrivateKey_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ed25519PrivateKey_setupDefaults(long cCtx) throws FoundationException;

    public native long ed25519PrivateKey_new();

    public native void ed25519PrivateKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ed25519PrivateKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo ed25519PrivateKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void ed25519PrivateKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int ed25519PrivateKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int ed25519PrivateKey_keyBitlen(long cCtx);

    /*
    * Generate new private or secret key.
    * Note, this operation can be slow.
    */
    public native void ed25519PrivateKey_generateKey(long cCtx) throws FoundationException;

    /*
    * Decrypt given data.
    */
    public native byte[] ed25519PrivateKey_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ed25519PrivateKey_decryptedLen(long cCtx, int dataLen);

    /*
    * Return length in bytes required to hold signature.
    */
    public native int ed25519PrivateKey_signatureLen(long cCtx);

    /*
    * Sign data given private key.
    */
    public native byte[] ed25519PrivateKey_signHash(long cCtx, byte[] hashDigest, AlgId hashId) throws FoundationException;

    /*
    * Extract public part of the key.
    */
    public native PublicKey ed25519PrivateKey_extractPublicKey(long cCtx);

    /*
    * Export private key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native byte[] ed25519PrivateKey_exportPrivateKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported private key.
    */
    public native int ed25519PrivateKey_exportedPrivateKeyLen(long cCtx);

    /*
    * Import private key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native void ed25519PrivateKey_importPrivateKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, shared key can be used only for symmetric cryptography.
    */
    public native byte[] ed25519PrivateKey_computeSharedKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    */
    public native int ed25519PrivateKey_sharedKeyLen(long cCtx);

    public native void curve25519PublicKey_setRandom(long cCtx, Random random);

    public native void curve25519PublicKey_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void curve25519PublicKey_setupDefaults(long cCtx) throws FoundationException;

    public native long curve25519PublicKey_new();

    public native void curve25519PublicKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId curve25519PublicKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo curve25519PublicKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void curve25519PublicKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int curve25519PublicKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int curve25519PublicKey_keyBitlen(long cCtx);

    /*
    * Encrypt given data.
    */
    public native byte[] curve25519PublicKey_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int curve25519PublicKey_encryptedLen(long cCtx, int dataLen);

    /*
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native byte[] curve25519PublicKey_exportPublicKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported public key.
    */
    public native int curve25519PublicKey_exportedPublicKeyLen(long cCtx);

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public native void curve25519PublicKey_importPublicKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Generate ephemeral private key of the same type.
    */
    public native PrivateKey curve25519PublicKey_generateEphemeralKey(long cCtx) throws FoundationException;

    public native void curve25519PrivateKey_setRandom(long cCtx, Random random);

    public native void curve25519PrivateKey_setEcies(long cCtx, Ecies ecies);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void curve25519PrivateKey_setupDefaults(long cCtx) throws FoundationException;

    public native long curve25519PrivateKey_new();

    public native void curve25519PrivateKey_close(long cCtx);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId curve25519PrivateKey_algId(long cCtx);

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public native AlgInfo curve25519PrivateKey_produceAlgInfo(long cCtx);

    /*
    * Restore algorithm configuration from the given object.
    */
    public native void curve25519PrivateKey_restoreAlgInfo(long cCtx, AlgInfo algInfo) throws FoundationException;

    /*
    * Length of the key in bytes.
    */
    public native int curve25519PrivateKey_keyLen(long cCtx);

    /*
    * Length of the key in bits.
    */
    public native int curve25519PrivateKey_keyBitlen(long cCtx);

    /*
    * Generate new private or secret key.
    * Note, this operation can be slow.
    */
    public native void curve25519PrivateKey_generateKey(long cCtx) throws FoundationException;

    /*
    * Decrypt given data.
    */
    public native byte[] curve25519PrivateKey_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int curve25519PrivateKey_decryptedLen(long cCtx, int dataLen);

    /*
    * Extract public part of the key.
    */
    public native PublicKey curve25519PrivateKey_extractPublicKey(long cCtx);

    /*
    * Export private key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native byte[] curve25519PrivateKey_exportPrivateKey(long cCtx) throws FoundationException;

    /*
    * Return length in bytes required to hold exported private key.
    */
    public native int curve25519PrivateKey_exportedPrivateKeyLen(long cCtx);

    /*
    * Import private key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public native void curve25519PrivateKey_importPrivateKey(long cCtx, byte[] data) throws FoundationException;

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, shared key can be used only for symmetric cryptography.
    */
    public native byte[] curve25519PrivateKey_computeSharedKey(long cCtx, PublicKey publicKey) throws FoundationException;

    /*
    * Return number of bytes required to hold shared key.
    */
    public native int curve25519PrivateKey_sharedKeyLen(long cCtx);

    public native void ecies_setRandom(long cCtx, Random random);

    public native void ecies_setCipher(long cCtx, Cipher cipher);

    public native void ecies_setMac(long cCtx, Mac mac);

    public native void ecies_setKdf(long cCtx, Kdf kdf);

    /*
    * Set public key that is used for data encryption.
    *
    * If ephemeral key is not defined, then Public Key, must be conformed
    * to the interface "generate ephemeral key".
    *
    * In turn, Ephemeral Key must be conformed to the interface
    * "compute shared key".
    */
    public native void ecies_setEncryptionKey(long cCtx, PublicKey encryptionKey);

    /*
    * Set private key that used for data decryption.
    *
    * Private Key must be conformed to the interface "compute shared key".
    */
    public native void ecies_setDecryptionKey(long cCtx, PrivateKey decryptionKey);

    /*
    * Set private key that used for data decryption.
    *
    * Ephemeral Key must be conformed to the interface "compute shared key".
    */
    public native void ecies_setEphemeralKey(long cCtx, PrivateKey ephemeralKey);

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public native void ecies_setupDefaults(long cCtx) throws FoundationException;

    public native long ecies_new();

    public native void ecies_close(long cCtx);

    /*
    * Encrypt given data.
    */
    public native byte[] ecies_encrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public native int ecies_encryptedLen(long cCtx, int dataLen);

    /*
    * Decrypt given data.
    */
    public native byte[] ecies_decrypt(long cCtx, byte[] data) throws FoundationException;

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public native int ecies_decryptedLen(long cCtx, int dataLen);

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
    public native OidId ecAlgInfo_keyId(long cCtx);

    /*
    * Return EC domain group identificator.
    */
    public native OidId ecAlgInfo_domainId(long cCtx);

    public native long ecAlgInfo_new();

    public native void ecAlgInfo_close(long cCtx);

    public native long ecAlgInfo_new(AlgId algId, OidId keyId, OidId domainId);

    /*
    * Provide algorithm identificator.
    */
    public native AlgId ecAlgInfo_algId(long cCtx);

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
}

