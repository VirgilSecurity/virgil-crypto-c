/* eslint-env jest */

const { PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, ACCOUNT_KEY_LENGTH } = require('./constants');
const { Client, Server } = require('./index');

describe('Client', () => {
  let client;
  let server;

  beforeEach(() => {
    client = new Client();
    server = new Server();
  });

  it("should throw if invoked without 'new'", () => {
    const error = () => Client();
    expect(error).toThrow();
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
      expect(clientPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
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
      expect(accountKey).toHaveLength(ACCOUNT_KEY_LENGTH);
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
      expect(result.newClientPrivateKey).toHaveLength(PRIVATE_KEY_LENGTH);
      expect(Buffer.isBuffer(result.newServerPublicKey)).toBeTruthy();
      expect(result.newServerPublicKey).toHaveLength(PUBLIC_KEY_LENGTH);
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
