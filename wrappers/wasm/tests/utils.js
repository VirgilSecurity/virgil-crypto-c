const hexToUint8Array = str => {
  if (str.length % 2 !== 0) {
    throw new TypeError('Hex string length must be divisible by 2');
  }
  return Uint8Array.from(str.match(/.{1,2}/g).map(element => parseInt(element, 16)));
};

module.exports.hexToUint8Array = hexToUint8Array;
