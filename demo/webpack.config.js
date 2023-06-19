const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");
// const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");

const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "development",
  entry: "./js/index.js",
  output: {
    path: dist,
    filename: "index.js",
  },
  devtool: 'source-map',
  stats: 'verbose',
  devServer: {
    contentBase: dist,
    writeToDisk: true
  },
  plugins: [
    new CopyPlugin([
      path.resolve(__dirname, "static")
    ]),

  //   new WasmPackPlugin({
  //     crateDirectory: path.resolve(__dirname, 'kos'),
  //     args: '--log-level warn',
  //      extraArgs: '---target bundler',
  //      outDir: "pkg",
  //   }),
  ]
};
