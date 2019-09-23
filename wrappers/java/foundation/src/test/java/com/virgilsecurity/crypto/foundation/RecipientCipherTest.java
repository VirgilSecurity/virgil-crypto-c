package com.virgilsecurity.crypto.foundation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import java.nio.charset.StandardCharsets;

import org.apache.commons.lang.ArrayUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RecipientCipherTest extends SampleBasedTest {

	private static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE".getBytes(StandardCharsets.UTF_8);
	private static final byte[] CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID".getBytes(StandardCharsets.UTF_8);

	private RecipientCipher recipientCipher;

	@Before
	public void setup() {
		this.recipientCipher = new RecipientCipher();
	}

	@After
	public void tearDown() {
		this.recipientCipher.close();
	}

	@Test
	public void encrypt_decrypt__with_ed25519() {
		byte[] data = getBytes("data");
		byte[] recipientId = new byte[] { 0x01, 0x02, 0x03 };

		try (Ed25519 ed = new Ed25519()) {
			ed.setupDefaults();

			try (RawPrivateKey privateKey = (RawPrivateKey) ed.generateKey()) {

				// Encrypt
				this.recipientCipher.addKeyRecipient(recipientId, privateKey.extractPublicKey());
				this.recipientCipher.customParams().addData(CUSTOM_PARAM_SIGNER_ID, CUSTOM_PARAM_SIGNER_ID);
				this.recipientCipher.customParams().addData(CUSTOM_PARAM_SIGNATURE, CUSTOM_PARAM_SIGNATURE);

				this.recipientCipher.startEncryption();

				byte[] messageInfo = this.recipientCipher.packMessageInfo();
				assertNotNull(messageInfo);

				byte[] processEncryptionData = this.recipientCipher.processEncryption(data);
				assertNotNull(processEncryptionData);

				byte[] finishEncryptionData = this.recipientCipher.finishEncryption();
				assertNotNull(finishEncryptionData);

				byte[] encryptedData = ArrayUtils.addAll(messageInfo,
						ArrayUtils.addAll(processEncryptionData, finishEncryptionData));

				// Decrypt
				try (RecipientCipher cipher = new RecipientCipher()) {
					cipher.startDecryptionWithKey(recipientId, privateKey, new byte[0]);

					byte[] processDecryptionData = cipher.processDecryption(encryptedData);
					assertNotNull(processDecryptionData);

					byte[] finishDecryptionData = cipher.finishDecryption();
					assertNotNull(finishDecryptionData);

					byte[] decryptedData = ArrayUtils.addAll(processDecryptionData, finishDecryptionData);
					assertArrayEquals(data, decryptedData);
				}
			}
		}
	}

	@Test
	public void encrypt_decrypt__with_rsa() {
		byte[] data = getBytes("data");
		byte[] recipientId = new byte[] { 0x01, 0x02, 0x03 };

		try (Rsa rsa = new Rsa()) {
			rsa.setupDefaults();

			try (RsaPrivateKey privateKey = (RsaPrivateKey) rsa.generateKey(2048)) {

				// Encrypt
				this.recipientCipher.addKeyRecipient(recipientId, privateKey.extractPublicKey());
				this.recipientCipher.customParams().addData(CUSTOM_PARAM_SIGNER_ID, CUSTOM_PARAM_SIGNER_ID);
				this.recipientCipher.customParams().addData(CUSTOM_PARAM_SIGNATURE, CUSTOM_PARAM_SIGNATURE);

				this.recipientCipher.startEncryption();

				byte[] messageInfo = this.recipientCipher.packMessageInfo();
				assertNotNull(messageInfo);

				byte[] processEncryptionData = this.recipientCipher.processEncryption(data);
				assertNotNull(processEncryptionData);

				byte[] finishEncryptionData = this.recipientCipher.finishEncryption();
				assertNotNull(finishEncryptionData);

				byte[] encryptedData = ArrayUtils.addAll(messageInfo,
						ArrayUtils.addAll(processEncryptionData, finishEncryptionData));

				// Decrypt
				try (RecipientCipher cipher = new RecipientCipher()) {
					cipher.startDecryptionWithKey(recipientId, privateKey, new byte[0]);

					byte[] processDecryptionData = cipher.processDecryption(encryptedData);
					assertNotNull(processDecryptionData);

					byte[] finishDecryptionData = cipher.finishDecryption();
					assertNotNull(finishDecryptionData);

					byte[] decryptedData = ArrayUtils.addAll(processDecryptionData, finishDecryptionData);
					assertArrayEquals(data, decryptedData);
				}
			}
		}
	}

}
