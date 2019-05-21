const path = require('path');

const builtinModules = require('builtin-modules');
const commonjs = require('rollup-plugin-commonjs');
const copy = require('rollup-plugin-copy');
const nodeResolve = require('rollup-plugin-node-resolve');

const UMD_NAME = 'Foundation';

const wasmBuildRoot = path.join(__dirname, '..', '..', '..', 'build', 'wrappers', 'wasm', 'foundation');
const sourceRoot = path.join(__dirname, 'src');
const outputFolder = path.join(__dirname, 'dist');

const builtinModulesMap = builtinModules.reduce((result, item) => {
  result[item] = item;
  return result;
}, {});

const format = process.env.FORMAT;
const formats = {
  cjs: 'cjs',
  es: 'es',
  umd: 'umd',
};
if (!formats[format]) {
  throw new TypeError(`'${format}' is not a valid format`);
}

module.exports = {
  input: path.join(sourceRoot, 'index.js'),
  output: {
    format,
    file: path.join(outputFolder, `foundation.${format}.js`),
    name: UMD_NAME,
  },
  plugins: [
    nodeResolve(),
    commonjs({
      ignoreGlobal: true,
      ignore: id => typeof builtinModulesMap[id] !== 'undefined',
    }),
    copy({
      targets: [
        path.join(wasmBuildRoot, 'libvsc_foundation.wasm'),
      ],
      outputFolder: outputFolder,
    }),
  ],
};
