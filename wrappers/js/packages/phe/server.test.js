/* eslint-env jest */

const { Client, Server } = require('./');

describe('Server', () => {
  let server;

  beforeEach(() => {
    server = new Server();
  });

  describe('generateServerKeypair', () => {
    it('should return private key and public key', () => {
      const result = server.generateServerKeypair();
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.privateKey)).toBeTruthy();
      expect(Buffer.isBuffer(result.publicKey)).toBeTruthy();
    });
  });

  describe('getEnrollment', () => {
    it('should return enrollment response', () => {
      const { privateKey, publicKey } = server.generateServerKeypair();
      const enrollmentResponse = server.getEnrollment(privateKey, publicKey);
      expect(Buffer.isBuffer(enrollmentResponse)).toBeTruthy();
    });
  });

  describe('verifyPassword', () => {
    it('should return verify password response', () => {
      const client = new Client();
      const { privateKey: clientPrivateKey } = server.generateServerKeypair();
      const {
        privateKey: serverPrivateKey,
        publicKey: serverPublicKey,
      } = server.generateServerKeypair();
      const password = Buffer.from('password');
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const { enrollmentRecord } = client.enrollAccount(
        clientPrivateKey,
        serverPublicKey,
        enrollmentResponse,
        password,
      );
      const verifyPasswordRequest = client.passwordVerifyRequest(
        clientPrivateKey,
        serverPublicKey,
        enrollmentRecord,
        password,
      );
      const verifyPasswordResponse = server.verifyPassword(
        serverPrivateKey,
        serverPublicKey,
        verifyPasswordRequest,
      );
      expect(Buffer.isBuffer(verifyPasswordResponse)).toBeTruthy();
    });
  });
});
