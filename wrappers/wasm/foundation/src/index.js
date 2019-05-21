const EmscriptenModule = require('../../../../build/wrappers/wasm/foundation/libvsc_foundation');
const initSha256 = require('./sha256');

const emscriptenModule = new EmscriptenModule();
let initPromise;

const initFoundation = () => {
  if (initPromise) {
    return initPromise;
  }
  initPromise = new Promise((resolve, reject) => {
    emscriptenModule.onRuntimeInitialized = () => {
      resolve({
        Sha256: initSha256(emscriptenModule),
      });
    };
    emscriptenModule.onAbort = message => {
      reject(new Error(message));
    };
  });
  return initPromise;
};

module.exports = initFoundation;
