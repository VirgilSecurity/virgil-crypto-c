const fs = require('fs');
const path = require('path');

const builtinModules = require('builtin-modules');
const commonjs = require('rollup-plugin-commonjs');
const copy = require('rollup-plugin-copy');
const nodeResolve = require('rollup-plugin-node-resolve');
const replace = require('rollup-plugin-replace');
const { terser } = require('rollup-plugin-terser');

const builtinModulesMap = builtinModules.reduce((result, item) => {
  result[item] = item;
  return result;
}, {});

const formats = ['cjs', 'es'];

const project = process.env.PROJECT;
if (typeof project !== 'string') {
  throw new TypeError(`'${project}' is not a valid project`);
}

const sourcePath = path.join(__dirname, project);
const outputPath = path.join(__dirname, 'dist', project);

const createEntry = (inputFilePath, libraryFilePath, format, outputFilePath) => ({
  input: inputFilePath,
  output: {
    format,
    file: outputFilePath,
  },
  plugins: [
    replace({
      'process.env.PROJECT_MODULE': JSON.stringify(libraryFilePath),
    }),
    nodeResolve(),
    commonjs({
      ignoreGlobal: true,
      ignore: id => typeof builtinModulesMap[id] !== 'undefined',
    }),
  ],
});

const createWasmEntry = (inputFilePath, libraryFilePath, wasmFilePath, format, outputFilePath) => {
  const entry = createEntry(inputFilePath, libraryFilePath, format, outputFilePath);
  entry.plugins.push(
    terser(),
    copy({ targets: [wasmFilePath], outputFolder: path.dirname(outputFilePath) }),
  );
  return entry;
};

const createAsmjsEntry = (inputFilePath, libraryFilePath, format, outputFilePath) => {
  const entry = createEntry(inputFilePath, libraryFilePath, format, outputFilePath);
  entry.plugins.push(terser());
  return entry;
};

const createEntries = format => [
  createWasmEntry(
    path.join(sourcePath, 'index.js'),
    path.join(sourcePath, `lib${project}.js`),
    path.join(sourcePath, `lib${project}.wasm`),
    format,
    path.join(outputPath, `node.${format}.js`),
  ),
  createWasmEntry(
    path.join(sourcePath, 'index.js'),
    path.join(sourcePath, `lib${project}.browser.js`),
    path.join(sourcePath, `lib${project}.browser.wasm`),
    format,
    path.join(outputPath, `browser.${format}.js`),
  ),
  createWasmEntry(
    path.join(sourcePath, 'index.js'),
    path.join(sourcePath, `lib${project}.worker.js`),
    path.join(sourcePath, `lib${project}.worker.wasm`),
    format,
    path.join(outputPath, `worker.${format}.js`),
  ),
  createAsmjsEntry(
    path.join(sourcePath, 'asmjs.js'),
    path.join(sourcePath, `lib${project}.asmjs.js`),
    format,
    path.join(outputPath, `node.asmjs.${format}.js`),
  ),
  createAsmjsEntry(
    path.join(sourcePath, 'asmjs.js'),
    path.join(sourcePath, `lib${project}.browser.asmjs.js`),
    format,
    path.join(outputPath, `browser.asmjs.${format}.js`),
  ),
  createAsmjsEntry(
    path.join(sourcePath, 'asmjs.js'),
    path.join(sourcePath, `lib${project}.worker.asmjs.js`),
    format,
    path.join(outputPath, `worker.asmjs.${format}.js`),
  ),
];

module.exports = formats.map(createEntries).reduce((result, entries) => result.concat(entries), []);
