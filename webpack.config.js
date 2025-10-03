const path = require('path');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const webpack = require('webpack');
const Dotenv = require('dotenv-webpack');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  entry: {
    popup: './src/Popup.tsx',
    background: './src/background.ts',
    content: './src/content.ts',
    alert: './src/alert.ts',
  },
  mode: 'development',
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js'],
    fallback: {
      "path": require.resolve("path-browserify"),
      "os": require.resolve("os-browserify/browser"),
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "events": require.resolve("events"),
      "vm": require.resolve("vm-browserify")
    },
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist'),
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: [
        {
          from: 'src/manifest.json',
          to: 'manifest.json',
          transform(content) {
            const manifest = JSON.parse(content.toString());

            // For Chrome/Edge (Manifest V3)
            if (process.env.TARGET_BROWSER === 'chrome') {
              return JSON.stringify(manifest, null, 2);
            }

            // For Firefox (Manifest V2 compatibility)
            if (process.env.TARGET_BROWSER === 'firefox') {
              manifest.manifest_version = 2;
              manifest.background = {
                scripts: ["background.js"],
                persistent: false
              };
              manifest.browser_action = manifest.action;
              delete manifest.action;
              delete manifest.host_permissions;
              manifest.permissions = [...(manifest.permissions || []), "*://*/*"];
              manifest.content_security_policy = manifest.content_security_policy?.extension_pages || "script-src 'self'; object-src 'self'";
              if (typeof manifest.content_security_policy === 'object') {
                manifest.content_security_policy = manifest.content_security_policy.extension_pages;
              }
            }

            return JSON.stringify(manifest, null, 2);
          }
        },
        { from: 'src/icons', to: 'icons' },
      ],
    }),
    new HtmlWebpackPlugin({
      template: './src/popup_template.html',
      filename: 'popup.html',
      chunks: ['popup']
    }),
    new HtmlWebpackPlugin({
      template: './src/alert.html',
      filename: 'alert.html',
      chunks: ['alert']
    }),
    new webpack.ProvidePlugin({
      process: 'process/browser',
    }),
    new Dotenv(),
  ],
  devServer: {
    contentBase: path.join(__dirname, 'dist'),
    compress: true,
    port: 9000,
  },
};