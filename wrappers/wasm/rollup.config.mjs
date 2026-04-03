import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

import commonjs from '@rollup/plugin-commonjs';
import copy from 'rollup-plugin-copy';
import nodeResolve from '@rollup/plugin-node-resolve';
import replace from '@rollup/plugin-replace';
import terser from '@rollup/plugin-terser';

const require = createRequire(import.meta.url);
const builtinModules = require('module').builtinModules;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
      preventAssignment: true,
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
    copy({ targets: [{ src: wasmFilePath, dest: path.dirname(outputFilePath) }] }),
  );
  return entry;
};

const createEntries = format => [
  createWasmEntry(
    path.join(sourcePath, 'index.js'),
    path.join(sourcePath, `lib${project}.js`),
    path.join(sourcePath, `lib${project}.wasm`),
    format,
    path.join(outputPath, `node.${format}.${format === 'cjs' ? 'js' : 'mjs'}`),
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
];

export default [
  ...formats.map(createEntries).reduce((result, entries) => result.concat(entries), []),
];
