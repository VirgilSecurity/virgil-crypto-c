const path = require('path');

const closureCompiler = require('@ampproject/rollup-plugin-closure-compiler');
const builtinModules = require('builtin-modules');
const commonjs = require('rollup-plugin-commonjs');
const copy = require('rollup-plugin-copy');
const nodeResolve = require('rollup-plugin-node-resolve');
const { terser } = require('rollup-plugin-terser');

const builtinModulesMap = builtinModules.reduce((result, item) => {
  result[item] = item;
  return result;
}, {});

const project = process.env.PROJECT;
if (typeof project !== 'string') {
  throw new TypeError(`'$(project)' is not a valid project`);
}

const format = 'es';

const sourcePath = path.join(__dirname, project);
const outputPath = path.join(__dirname, 'dist');

const wasmInputPath = path.join(sourcePath, 'index.js');
const wasmFilePath = path.join(sourcePath, `lib${project}.wasm`);
const wasmOutputPath = path.join(outputPath, `${project}.js`);

const asmjsInputPath = path.join(sourcePath, 'asmjs.js');
const asmjsOutputPath = path.join(outputPath, `${project}.asmjs.js`);

module.exports = [
  {
    input: wasmInputPath,
    output: {
      format,
      file: wasmOutputPath,
    },
    plugins: [
      nodeResolve(),
      commonjs({
        ignoreGlobal: true,
        ignore: id => typeof builtinModulesMap[id] !== 'undefined',
      }),
      closureCompiler(),
      terser(),
      copy({
        targets: [wasmFilePath],
        outputFolder: outputPath,
      }),
    ],
  },
  {
    input: asmjsInputPath,
    output: {
      format,
      file: asmjsOutputPath,
    },
    plugins: [
      nodeResolve(),
      commonjs({
        ignoreGlobal: true,
        ignore: id => typeof builtinModulesMap[id] !== 'undefined',
      }),
      closureCompiler(),
      terser(),
    ],
  },
];
