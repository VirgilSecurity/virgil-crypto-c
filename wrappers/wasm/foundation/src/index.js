const Module = require('../../../../build/wrappers/wasm/foundation/libvsc_foundation');
const initSha256 = require('./sha256');

let initPromise;

const initFoundation = () => {
  if (initPromise) {
    return initPromise;
  }
  initPromise = new Promise((resolve, reject) => {
    Module.onRuntimeInitialized = () => {
      resolve({
        Sha256: initSha256(Module),
      });
    };
    Module.onAbort = what => {
      reject(new Error(what));
    };
  });
  return initPromise;
};

module.exports = initFoundation;
