const path = require('path');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');

module.exports = {
    mode: "production",
    entry: './src/index.js',
    output: {
        filename: 'index.js',
        path: path.resolve(__dirname, 'dist'),
        library: 'eos_aws_cognito',
        libraryTarget: 'umd',
        globalObject: 'this'
    },
    target: ['browserslist:defaults, not ie <= 11'],
    plugins: [
        new CleanWebpackPlugin({ cleanStaleWebpackAssets: false })
    ],
    module: {
      rules: [
        {
          test: /\.m?js$/,
          exclude: /(node_modules|bower_components)/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: [['@babel/preset-env', {"useBuiltIns": "usage", "corejs": "3.8"}]],
              plugins: ['@babel/plugin-proposal-class-properties']
            }
          }
        }
      ]
    }
};