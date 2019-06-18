const initPhe = require('../../dist/phe/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('PheClient', () => {
  let phe;
  let pheClient;

  beforeEach(async () => {
    phe = await initPhe();
    pheClient = new phe.PheClient();
    pheServer = new phe.PheServer();
    pheClient.setupDefaults();
    pheServer.setupDefaults();
  });

  describe('enrollAccount', () => {
    it('should work', () => {
      const serverKeyPair = pheServer.generateServerKeyPair();
      const clientKeyPair = pheServer.generateServerKeyPair();
      pheClient.setKeys(clientKeyPair.serverPrivateKey, serverKeyPair.serverPublicKey);
      const enrollment = pheServer.getEnrollment(
        serverKeyPair.serverPrivateKey,
        serverKeyPair.serverPublicKey,
      );
      const password = hexToUint8Array('70617373776f7264');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      expect(enrollmentRecord).toBeInstanceOf(Uint8Array);
      expect(accountKey).toBeInstanceOf(Uint8Array);
    });
  });

  describe('createVerifyPasswordRequest', () => {
    it('should work', () => {
      const serverKeyPair = pheServer.generateServerKeyPair();
      const clientKeyPair = pheServer.generateServerKeyPair();
      pheClient.setKeys(clientKeyPair.serverPrivateKey, serverKeyPair.serverPublicKey);
      const enrollment = pheServer.getEnrollment(
        serverKeyPair.serverPrivateKey,
        serverKeyPair.serverPublicKey,
      );
      const password = hexToUint8Array('70617373776f7264');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      const request = pheClient.createVerifyPasswordRequest(password, enrollmentRecord);
      expect(request).toBeInstanceOf(Uint8Array);
    });
  });

  describe('checkResponseAndDecrypt', () => {
    it('should work', () => {
      const serverKeyPair = pheServer.generateServerKeyPair();
      const clientKeyPair = pheServer.generateServerKeyPair();
      pheClient.setKeys(clientKeyPair.serverPrivateKey, serverKeyPair.serverPublicKey);
      const enrollment = pheServer.getEnrollment(
        serverKeyPair.serverPrivateKey,
        serverKeyPair.serverPublicKey,
      );
      const password = hexToUint8Array('70617373776f7264');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      const request = pheClient.createVerifyPasswordRequest(password, enrollmentRecord);
      const response = pheServer.verifyPassword(
        serverKeyPair.serverPrivateKey,
        serverKeyPair.serverPublicKey,
        request,
      );
      const myAccountKey = pheClient.checkResponseAndDecrypt(password, enrollmentRecord, response);
      expect(myAccountKey.toString()).toBe(accountKey.toString());
    });
  });
});
