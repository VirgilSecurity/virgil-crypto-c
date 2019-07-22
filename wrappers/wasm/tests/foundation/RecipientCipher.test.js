const initFoundation = require('../../dist/foundation/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('RecipientCipher', () => {
  let foundation;
  let recipientCipher;

  beforeEach(async () => {
    foundation = await initFoundation();
    recipientCipher = new foundation.RecipientCipher();
  });

  test('encrypt / decrypt with ed25519 key pair', () => {
    const ed25519 = new foundation.Ed25519();
    ed25519.setupDefaults();
    const privateKey = ed25519.generateKey();
    const publicKey = privateKey.getPublicKey();
    const recipientId = hexToUint8Array('726563697069656e74');
    recipientCipher.addKeyRecipient(recipientId, publicKey);
    recipientCipher.startEncryption();
    const data = hexToUint8Array('64617461');
    const messageInfo = recipientCipher.packMessageInfo();
    const processEncryption = recipientCipher.processEncryption(data);
    const finishEncryption = recipientCipher.finishEncryption();
    const encryptedMessage = new Uint8Array(
      messageInfo.length + processEncryption.length + finishEncryption.length,
    );
    encryptedMessage.set(messageInfo);
    encryptedMessage.set(processEncryption, messageInfo.length);
    encryptedMessage.set(finishEncryption, messageInfo.length + processEncryption.length);
    recipientCipher.startDecryptionWithKey(recipientId, privateKey, new Uint8Array());
    const processDecryption = recipientCipher.processDecryption(encryptedMessage);
    const finishDecryption = recipientCipher.finishDecryption();
    const result = new Uint8Array(processDecryption.length + finishDecryption.length);
    result.set(processDecryption);
    result.set(finishDecryption, processDecryption.length);
    expect(result.toString()).toBe(data.toString());
  });
});
