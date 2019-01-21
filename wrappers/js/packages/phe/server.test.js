/* eslint-env jest */

const { PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH } = require('./constants');
const { Client, Server } = require('./index');

describe('Server', () => {
  let server;

  beforeEach(() => {
    server = new Server();
  });

  it("should throw if invoked without 'new'", () => {
    const error = () => Server();
    expect(error).toThrow();
  });

  describe('generateServerKeyPair', () => {
    it('should return server private key and server public key', () => {
      const result = server.generateServerKeyPair();
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.serverPrivateKey)).toBeTruthy();
      expect(result.serverPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
      expect(Buffer.isBuffer(result.serverPublicKey)).toBeTruthy();
      expect(result.serverPublicKey).toHaveLength(PUBLIC_KEY_LENGTH);
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
      expect(result.newServerPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
      expect(Buffer.isBuffer(result.newServerPublicKey)).toBeTruthy();
      expect(result.newServerPublicKey).toHaveLength(PUBLIC_KEY_LENGTH);
      expect(Buffer.isBuffer(result.updateToken)).toBeTruthy();
    });
  });
});
