const initFoundation = require('../../foundation');

describe('RecipientCipher', () => {
  let foundation;
  let recipientCipher;

  beforeEach(async () => {
    foundation = await initFoundation();
    recipientCipher = new foundation.RecipientCipher();
  });

  test('encrypt / decrypt with ed25519 key recipient', () => {
    const keyDeserializer = new foundation.KeyAsn1Deserializer();
    keyDeserializer.setupDefaults();
    const publicKeyBuffer = Buffer.from(
      '302a300506032b657003210086614074b7a5d1130448be69a4a25ce58dbf760a87bbf92a03add973f38ece7c',
      'hex',
    );
    const rawPublicKey = keyDeserializer.deserializePublicKey(publicKeyBuffer);
    const publicKey = foundation.AlgFactory.createPublicKeyFromRawKey(rawPublicKey);
    const privateKeyBuffer = Buffer.from(
      '302e020100300506032b65700422042010da87566b446edb74afa6eb6754774367081efa5fcd39c19e64a36830445b1b',
      'hex',
    );
    const rawPrivateKey = keyDeserializer.deserializePrivateKey(privateKeyBuffer);
    const privateKey = foundation.AlgFactory.createPrivateKeyFromRawKey(rawPrivateKey);
    const recipientCipher = new foundation.RecipientCipher();
    const recipientId = Buffer.from(
      '6a078258df744e6a91ef004057faa4b24d339fb1c03d6c19c5ed52ebb520a3b4',
      'hex',
    );
    recipientCipher.addKeyRecipient(recipientId, publicKey);
    recipientCipher.startEncryption();
    const encrypted1 = recipientCipher.packMessageInfo();
    const message = Buffer.from(
      '56697267696c205365637572697479204c69627261727920666f7220430a',
      'hex',
    );
    const encrypted2 = recipientCipher.processEncryption(message);
    const encrypted3 = recipientCipher.finishEncryption();
    const encryptedMessage = new Uint8Array(
      encrypted1.length + encrypted2.length + encrypted3.length,
    );
    encryptedMessage.set(encrypted1);
    encryptedMessage.set(encrypted2, encrypted1.length);
    encryptedMessage.set(encrypted3, encrypted1.length + encrypted2.length);
    const messageInfo = Buffer.alloc(0);
    recipientCipher.startDecryptionWithKey(recipientId, privateKey, messageInfo);
    const decrypted1 = recipientCipher.processDecryption(encryptedMessage);
    const decrypted2 = recipientCipher.finishDecryption();
    const result = new Uint8Array(decrypted1.length + decrypted2.length);
    result.set(decrypted1);
    result.set(decrypted2, decrypted1.length);
    expect(Buffer.compare(result, message)).toBe(0);
  });

  test('decrypt with ed25519 public key', () => {
    const keyDeserializer = new foundation.KeyAsn1Deserializer();
    keyDeserializer.setupDefaults();
    const privateKeyBuffer = Buffer.from(
      '302e020100300506032b65700422042010da87566b446edb74afa6eb6754774367081efa5fcd39c19e64a36830445b1b',
      'hex',
    );
    const rawPrivateKey = keyDeserializer.deserializePrivateKey(privateKeyBuffer);
    const privateKey = foundation.AlgFactory.createPrivateKeyFromRawKey(rawPrivateKey);
    const recipientCipher = new foundation.RecipientCipher();
    const recipientId = Buffer.from(
      '6a078258df744e6a91ef004057faa4b24d339fb1c03d6c19c5ed52ebb520a3b4',
      'hex',
    );
    const messageInfo = Buffer.alloc(0);
    recipientCipher.startDecryptionWithKey(recipientId, privateKey, messageInfo);
    const encryptedMessage = Buffer.from(
      '308201600201003082015906092a864886f70d010703a082014a308201460201023182011730820113020102a02204206a078258df744e6a91ef004057faa4b24d339fb1c03d6c19c5ed52ebb520a3b4300506032b65700481e23081df020100302a300506032b6570032100e2c5a1528c6801d466b7f8c726bd40cbf69eb3777982eab65661aead55c848943018060728818c71020502300d060960864801650304020205003041300d06096086480165030402020500043031264ee2b79bcd1d3018fd4ccb2a01d9f7e3a20c50de44c6914ef74b09b003277baee71f7f3d43d3c69b2af583d7b6443051301d060960864801650304012a0410be9ece2b4d387b2e488b452e1000758204307962974c37c5566fd64ef54a04b9a677c13644589443e124ca2afee98b2ae8d3630338d08e62f98710641c93d176ebb1302606092a864886f70d0107013019060960864801650304012e040c4bdee5fbecf47a6f8d8b3dd1a0b611add64bf4a3f88cb602fb4c979087c7a19a65743f578f9b7dbd550cc3b3307a7cbf1938aa8b19b53615cbb8370437a9c9488dcb63f327a3601920336a97a4767c68f992fbed9c3bd819ad6f1f445aef9e30df7926eaa7b5',
      'hex',
    );
    const decrypted1 = recipientCipher.processDecryption(encryptedMessage);
    const decrypted2 = recipientCipher.finishDecryption();
    const result = new Uint8Array(decrypted1.length + decrypted2.length);
    result.set(decrypted1);
    result.set(decrypted2, decrypted1.length);
    const expectedMessage = Buffer.from(
      '56697267696c205365637572697479204c69627261727920666f7220430a56697267696c205365637572697479204c69627261727920666f7220430a56697267696c2053656375726974',
      'hex',
    );
    expect(Buffer.compare(result, expectedMessage)).toBe(0);
  });
});
