/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020-2022 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 *
 * See https://bitbucket.org/yakoana/xapiripe/src/master/
 * webpack.config.js - Build to web-api
 * 
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3.0 of
 * the License, or (at your option) any later version.
 *
 * This application is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See https://opensource.org/licenses/LGPL-3.0
 *
 */

'use strict';

const webpack = require('webpack');
const path = require('path');
const project = path.dirname(__dirname);


let config = {
	bail: true,
	context: project,
	devtool: false,
	entry: path.join(project, 'web-api', 'xabo.js'),
	infrastructureLogging: {
		appendOnly: true,
		level: 'verbose',
		colors: true
	},
	mode: 'production',
	node: { global: true },
	output: {
		clean: true,
		filename: 'xapiripe.js',
		library: 'xabo',
		libraryExport: 'xabo',
		path: path.resolve(__dirname, 'output', 'web-api'),
		pathinfo: false
	},
	plugins: [
		new webpack.ProgressPlugin({
			activeModules: true,
			entries: true,
			modules: true,
			percentBy: 'modules'
		}),
		new webpack.ProvidePlugin({
			process: 'process/browser',
			Buffer: [ 'buffer', 'Buffer' ],
			setImmediate: ['timers-browserify', 'setImmediate']
		})
	],
	resolve: {
		fallback: {
			assert: require.resolve('assert'),
			fs: false,
			stream: require.resolve('stream-browserify'),
			util: require.resolve('util'),
			zlib: require.resolve('browserify-zlib')
		}
	},
	stats: { errorDetails: true },
	target: 'web'
};

module.exports = (env) => {
	if (env.development) {
		config.mode = 'development';
		config.devtool = 'inline-source-map';
		config.output.pathinfo = true;
	}
	return config;
};