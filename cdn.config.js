const path = require('path');


module.exports = {
    mode: "production",
    entry: './src/index.js',
    output: {
        filename: 'eos_aws_cognito.min.js',
        path: path.resolve(__dirname, 'dist'),
        library: 'eos_aws_cognito',
        libraryTarget: 'var'
    },
    devtool: false,
    target: ['browserslist:defaults, not ie <= 11'],
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