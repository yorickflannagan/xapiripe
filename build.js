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
 * build.js - Build facility
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

const path = require('path');
const fs = require('fs');
const packager = require('electron-packager');
const installer = require('electron-winstaller');
const yargs = require('yargs');
const { Distribution, uriPattern } = require('./components/options');

const svcSignet = new Distribution('org.crypthing.xapiripe.CriptoCNS', 'CriptoCNS', 'CriptoCNS REST service', 'CriptoCNS.exe');
const svcIconFile = path.resolve('./appservice/res/signature-32x32.ico');
const buildFolder = './build';
const svcDependencies = {
	'alert': '^5.1.1',
	'asn1js': '^2.3.2',
	'node-addon-api': '^4.3.0'
}
const svcBuildOptions = {
	appCopyright: 'Copyleft (C) 2020-2022 The Crypthing Initiative. All rights reversed.',
	arch: '',
	dir: '.',
	executableName: 'criptocns',
	icon: svcIconFile,
	ignore: [
		'.vscode',
		'docs/',
		'hamahiri/',
		'pki/',
		'test/',
		'web-api/',
		'signthing/',
		'options.json',
		'package-lock.json',
		'package-old.json',
		'.log',
		'.gitignore',
		'build.js',
		'make-docs',
		'install-spinner.gif',
		'webpack.config.js'
	],
	name: svcSignet.productName,
	out: path.resolve(buildFolder),
	overwrite: true,
	platform: 'win32',
	win32metadata: {
		CompanyName: svcSignet.company,
		ProductName:  svcSignet.productName,
		FileDescription: svcSignet.productDescription
	}
}
const svcExcludeDirs = [ 'docs', 'hamahiri', 'pki', 'test', 'web-api', 'signthing' ];

const packageFolder = buildFolder + '/installer';
const svcPackageOptions = {
	appDirectory: buildFolder + '/Hekura-win32-x64',
	outputDirectory: path.resolve(packageFolder),
	loadingGif: path.resolve('./install-spinner.gif'),
	authors: svcSignet.company,
	exe: svcSignet.exe,
	description: svcSignet.productDescription,
	title: svcSignet.productName,
	name : svcSignet.productName,
	iconUrl: svcIconFile,
	setupIcon: svcIconFile,
	setupExe: 'install-' + svcSignet.exe,
	noMsi: true
}

function mintSignet(signet, distributor, updateURL, target) {
	signet.distributorId = distributor;
	signet.updateURL = updateURL;
	fs.writeFileSync(target, JSON.stringify(signet));
	return signet;
}

function getVersion(jsfile) {
	let src = fs.readFileSync(jsfile, { encoding: 'utf-8' });
	let lines = src.split(/\r?\n/);
	let i = 0;
	while (i < lines.length) {
		let line = lines[i++];
		let idx = line.indexOf('@version');
		if (idx > -1)  return line.substring(idx + 8).trim();
	}
	throw new Error('File does not contains a version reference');
}

function mintPackage(entryPoint, backup, signet) {
	let version = getVersion(path.resolve(entryPoint));
	let source = path.resolve(__dirname, 'package.json');
	let pack = JSON.parse(fs.readFileSync(source));
	pack.name = signet.productName.toLowerCase();
	pack.version = version;
	pack.main = entryPoint;
	pack.dependencies = svcDependencies;
	fs.renameSync(source, backup);
	fs.writeFileSync(source, JSON.stringify(pack));
	return source;
}

function appPackage(options, excludeDirs) {
	return new Promise((resolve, reject) => {
		packager(options).then((appPaths) => {
			let target = path.resolve(appPaths[0], 'resources', 'app');
			let i = 0;
			while (i < excludeDirs.length) {
				let dir = path.resolve(target, excludeDirs[i++]);
				if (fs.existsSync(dir)) fs.rmdirSync(dir);
			}
			return resolve(appPaths[0]);
		}).catch((reason) => {
			return reject(reason);
		});
	});
}

function appInstaller(options) {
	return new Promise((resolve, reject) => {
		installer.createWindowsInstaller(options).then(() => {
			return resolve(true);
		}).catch((reason) => {
			return reject(reason);
		});
	});
}

/**
 * Linha de comando: node build.js [options], onde:
 * 	--build: string definindo a aplicação a ser construída, a saber: service | app. Obrigatório
 * 	--distributorId: string indicando o distribuidor da aplicação. Opcional. Default: org.crypthing.xapiripe
 * 	--updateURL: localização do servidor de atualização. Obrigatório.
 * 	--arch: string indicando a arquitetura de CPU alvo, a saber: x64 | ia32. Opcional. Default: x64
 */
(function () {
	const argv = yargs(process.argv).argv;
	let target = argv.build;
	let distributorId = argv.distributorId ? argv.distributorId : 'org.crypthing.xapiripe';
	let updateURL = argv.updateURL;
	let arch = argv.arch ? argv.arch : 'x64';
	let sourceDir;
	let signet;
	let buildOptions;
	let excludeDirs;
	let distributionFile;
	let packageOptions;

	switch (target) {
	case 'service':
		sourceDir = './appservice/main.js';
		signet = svcSignet;
		buildOptions = svcBuildOptions;
		excludeDirs = svcExcludeDirs;
		packageOptions = svcPackageOptions;
		distributionFile = './appservice/distribution.json';
		break;
	case 'app':
		throw new Error('--build=app not implemented yet');
		break;
	default: throw new Error('Invalid --build argument');
	}
	if (!target) throw new Error('Missing --build argument');
	if (!updateURL) throw new Error('Missing --updateURL argument');
	if (!updateURL.match(uriPattern)) throw new Error('Argument --updateURL must be a valid URL');
	let msg = 'Build arguments:'
		.concat('\n\t--build: ').concat(target)
		.concat('\n\t--distributorId: ').concat(distributorId)
		.concat('\n\t--updateURL: ').concat(updateURL)
		.concat('\n\t--arch: ').concat(arch);
	console.log(msg);

	let newSignet = mintSignet(signet, distributorId, updateURL, distributionFile);
	let backup = path.resolve(__dirname, 'package-old.json');
	let pack = mintPackage(sourceDir, backup, newSignet);
	buildOptions.arch = arch;
	msg = 'Standalone package will be built with the following definitions:'
		.concat('\nsignet: ').concat(JSON.stringify(newSignet, null, 2))
		.concat('\noptions: ').concat(JSON.stringify(buildOptions, null, 2));
	console.log(msg);
	appPackage(buildOptions, excludeDirs).then((appPath) => {
		console.log('Package built to path: ' + appPath);
		packageOptions.appDirectory = appPath;
		msg = 'Application installer will be generated with the following definitions:'
			.concat('\n').concat(JSON.stringify(packageOptions, null, 2))
			.concat('\nIt may take a long, long, long time. Please, be patient...');
		console.log(msg);
		appInstaller(packageOptions).then(() => {
			console.log('Application installer has been built... at last!');
			fs.unlinkSync(pack);
			fs.renameSync(backup, pack);
		}).catch((reason) => {
			console.error(reason);
			fs.unlinkSync(pack);
			fs.renameSync(backup, pack);
		});
	}).catch((reason) => {
		console.error(reason);
		fs.unlinkSync(pack);
		fs.renameSync(backup, pack);
	});
}());
