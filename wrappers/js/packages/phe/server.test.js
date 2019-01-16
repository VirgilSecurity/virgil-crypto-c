/* eslint-env jest */

const { Client, Server } = require('./');

describe('Server', () => {
  let server;

  beforeEach(() => {
    server = new Server();
  });

  describe('generateServerKeyPair', () => {
    it('should return server private key and server public key', () => {
      const result = server.generateServerKeyPair();
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.serverPrivateKey)).toBeTruthy();
      expect(Buffer.isBuffer(result.serverPublicKey)).toBeTruthy();
    });
  });

  describe('getEnrollment', () => {
    it('should return enrollment response', () => {
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      expect(Buffer.isBuffer(enrollmentResponse)).toBeTruthy();
    });
  });

  describe('verifyPassword', () => {
    it('should return verify password response', () => {
      const client = new Client();
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { enrollmentRecord } = client.enrollAccount(enrollmentResponse, password);
      const verifyPasswordRequest = client.createVerifyPasswordRequest(enrollmentRecord, password);
      const verifyPasswordResponse = server.verifyPassword(
        serverPrivateKey,
        serverPublicKey,
        verifyPasswordRequest,
      );
      expect(Buffer.isBuffer(verifyPasswordResponse)).toBeTruthy();
    });
  });

  describe('rotateKeys', () => {
    it('should return new server private key, new server public key and update token', () => {
      const { serverPrivateKey } = server.generateServerKeyPair();
      const result = server.rotateKeys(serverPrivateKey);
      expect(Object.keys(result)).toHaveLength(3);
      expect(Buffer.isBuffer(result.newServerPrivateKey)).toBeTruthy();
      expect(Buffer.isBuffer(result.newServerPublicKey)).toBeTruthy();
      expect(Buffer.isBuffer(result.updateToken)).toBeTruthy();
    });
  });
});
