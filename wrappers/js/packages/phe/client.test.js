/* eslint-env jest */

const { Client, Server } = require('./');

describe('Client', () => {
  let client;
  let clientPrivateKey;
  let server;
  let serverPrivateKey;
  let serverPublicKey;

  beforeEach(() => {
    client = new Client();
    server = new Server();
    const clientKeyPair = server.generateServerKeypair();
    const serverKeyPair = server.generateServerKeypair();
    clientPrivateKey = clientKeyPair.privateKey;
    serverPrivateKey = serverKeyPair.privateKey;
    serverPublicKey = serverKeyPair.publicKey;
  });

  describe('enrollAccount', () => {
    it('should return enrollment record and account key', () => {
      const password = Buffer.from('password');
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const result = client.enrollAccount(
        clientPrivateKey,
        serverPublicKey,
        enrollmentResponse,
        password,
      );
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.enrollmentRecord)).toBeTruthy();
      expect(Buffer.isBuffer(result.accountKey)).toBeTruthy();
    });
  });

  describe('passwordVerifyRequest', () => {
    it('should return verify password request', () => {
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
      expect(Buffer.isBuffer(verifyPasswordRequest)).toBeTruthy();
    });
  });

  describe('verifyServerResponse', () => {
    it('should return account key', () => {
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
      const accountKey = client.verifyServerResponse(
        clientPrivateKey,
        serverPublicKey,
        password,
        enrollmentRecord,
        verifyPasswordResponse,
      );
      expect(Buffer.isBuffer(accountKey)).toBeTruthy();
    });
  });
});
