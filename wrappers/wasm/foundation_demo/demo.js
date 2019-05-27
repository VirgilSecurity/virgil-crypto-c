const util = require('util');
const initFoundation = require('./dist/foundation.cjs');

const data2hex = data =>
  Array.prototype.map.call(data, x => ('00' + x.toString(16)).slice(-2)).join('');;

initFoundation().then(foundation => {
  const sha256 = new foundation.Sha256();
  const textEncoder = new util.TextEncoder();

  console.log('3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7');

  const data = textEncoder.encode('data');
  const digest1 = foundation.Sha256.hash(data);
  console.log(data2hex(digest1));

  sha256.start();
  sha256.update(textEncoder.encode('d'));
  sha256.update(textEncoder.encode('a'));
  sha256.update(textEncoder.encode('t'));
  sha256.update(textEncoder.encode('a'));
  const digest2 = sha256.finish();
  console.log(data2hex(digest2));

  sha256.free();
});
