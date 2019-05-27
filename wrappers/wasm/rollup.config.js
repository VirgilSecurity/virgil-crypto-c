const path = require('path');

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

const format = process.env.FORMAT;
const formats = {
  cjs: 'cjs',
  es: 'es',
  umd: 'umd',
};
if (!formats[format]) {
  throw new TypeError(`'${format}' is not a valid format`);
}

const packageJsonPath = path.join(__dirname, 'package.json');
const sourcePath = path.join(__dirname, project);
const inputPath = path.join(sourcePath, 'index.js');
const wasmPath = path.join(sourcePath, `lib${project}.wasm`);
const outputPath = path.join(__dirname, 'dist');
const outputFilePath = path.join(outputPath, `${project}.${format}.js`);
const umdName = project;

module.exports = {
  input: inputPath,
  output: {
    format,
    file: outputFilePath,
    name: umdName,
  },
  plugins: [
    nodeResolve(),
    commonjs({
      ignoreGlobal: true,
      ignore: id => typeof builtinModulesMap[id] !== 'undefined',
    }),
    terser(),
    copy({
      targets: [wasmPath, packageJsonPath],
      outputFolder: outputPath,
    }),
  ],
};
