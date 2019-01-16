/* eslint-env jest */

const { Client, Server } = require('./');

describe('Client', () => {
  let client;
  let server;

  beforeEach(() => {
    client = new Client();
    server = new Server();
  });

  describe('setKeys', () => {
    it('should work', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPublicKey } = server.generateServerKeyPair();
      const result = client.setKeys(clientPrivateKey, serverPublicKey);
      expect(result).toBeUndefined();
    });
  });

  describe('generateClientPrivateKey', () => {
    it('should return client private key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      expect(Buffer.isBuffer(clientPrivateKey)).toBeTruthy();
    });
  });

  describe('enrollAccount', () => {
    it('should return enrollment record and account key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const result = client.enrollAccount(enrollmentResponse, password);
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.enrollmentRecord)).toBeTruthy();
      expect(Buffer.isBuffer(result.accountKey)).toBeTruthy();
    });
  });

  describe('createVerifyPasswordRequest', () => {
    it('should return verify password request', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { enrollmentRecord } = client.enrollAccount(enrollmentResponse, password);
      const verifyPasswordRequest = client.createVerifyPasswordRequest(enrollmentRecord, password);
      expect(Buffer.isBuffer(verifyPasswordRequest)).toBeTruthy();
    });
  });

  describe('checkResponseAndDecrypt', () => {
    it('should return account key', () => {
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
      const accountKey = client.checkResponseAndDecrypt(
        password,
        enrollmentRecord,
        verifyPasswordResponse,
      );
      expect(Buffer.isBuffer(accountKey)).toBeTruthy();
    });
  });

  describe('rotateKeys', () => {
    it('should return new client private key and new server public key', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const { updateToken } = server.rotateKeys(serverPrivateKey);
      const result = client.rotateKeys(updateToken);
      expect(Object.keys(result)).toHaveLength(2);
      expect(Buffer.isBuffer(result.newClientPrivateKey)).toBeTruthy();
      expect(Buffer.isBuffer(result.newServerPublicKey)).toBeTruthy();
    });
  });

  describe('updateEnrollmentRecord', () => {
    it('should return updated enrollment record', () => {
      const clientPrivateKey = client.generateClientPrivateKey();
      const { serverPrivateKey, serverPublicKey } = server.generateServerKeyPair();
      client.setKeys(clientPrivateKey, serverPublicKey);
      const enrollmentResponse = server.getEnrollment(serverPrivateKey, serverPublicKey);
      const password = Buffer.from('password');
      const { enrollmentRecord } = client.enrollAccount(enrollmentResponse, password);
      const { updateToken } = server.rotateKeys(serverPrivateKey);
      const updatedEnrollmentRecord = client.updateEnrollmentRecord(enrollmentRecord, updateToken);
      expect(Buffer.isBuffer(updatedEnrollmentRecord)).toBeTruthy();
    });
  });
});
