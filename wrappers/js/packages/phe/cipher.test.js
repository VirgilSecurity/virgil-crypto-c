/* eslint-env jest */

const { Cipher, Client, Server } = require('./');

describe('Cipher', () => {
  let cipher;
  let client;
  let server;

  beforeEach(() => {
    cipher = new Cipher();
    client = new Client();
    server = new Server();
  });

  describe('encrypt', () => {
    it('should return cipher text', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { accountKey } = client.enrollAccount(enrollmentResponse, password);
      const plainText = Buffer.from('plaintext');
      const cipherText = cipher.encrypt(plainText, accountKey);
      expect(Buffer.isBuffer(cipherText)).toBeTruthy();
    });
  });

  describe('decrypt', () => {
    it('should return plain text', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { accountKey } = client.enrollAccount(enrollmentResponse, password);
      const plainText = Buffer.from('plaintext');
      const cipherText = cipher.encrypt(plainText, accountKey);
      const result = cipher.decrypt(cipherText, accountKey);
      expect(result).toEqual(plainText);
    });
  });
});
