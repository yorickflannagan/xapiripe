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
const { Distribution, uriPattern } = require('../components/options');


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
 * 	--arch: string indicando a arquitetura de CPU alvo, a saber: x64 | ia32. Opcional. Default: x64
 *  --distribution: caminho completo para o arquivo de configuração da distribuição. Obrigatório
 */
(function () {
	const argv = yargs(process.argv).argv;
	let target = argv.build;
	if (!target) throw new Error('Missing --build argument');
	let arch = argv.arch ? argv.arch : 'x64';
	let signet;
	try { signet = Distribution.load(path.resolve(argv.distribution)); }
	catch (e) { throw new Error('Argument --distribution must point to a valid Distribution JSON file: ' + e.toString()); }

	const project = path.dirname(__dirname);
	const svcIconFile = path.join(project, 'appservice', 'res', 'signature-32x32.ico');
	const buildFolder = path.resolve(__dirname, 'output');
	const svcDependencies = {
		'alert': '^5.1.1',
		'asn1js': '^2.3.2',
		'node-addon-api': '^4.3.0'
	}
	const svcBuildOptions = {
		appCopyright: 'Copyleft (C) 2020-2022 The Crypthing Initiative. All rights reversed.',
		arch: '',
		dir: project,
		executableName: signet.productName.toLowerCase(),
		icon: svcIconFile,
		ignore: [
			'.vscode/',
			'^/build/',
			'docs/',
			'hamahiri/',
			'pki/',
			'signthing/',
			'test/',
			'web-api/',
			'.gitignore',
			'.jshintrc',
			'history.md',
			'LEIA-ME.MD',
			'package-lock.json',
			'package-old.json'
		],
		name: signet.productName,
		out: buildFolder,
		overwrite: true,
		platform: 'win32',
		win32metadata: {
			CompanyName: signet.company,
			ProductName:  signet.productName,
			FileDescription: signet.productDescription
		}
	}
	const svcExcludeDirs = [ '.vscode', 'build', 'docs', 'hamahiri', 'pki', 'signthing', 'test', 'web-api' ];
	const packageFolder = path.join(buildFolder, 'installer');
	const svcPackageOptions = {
		appDirectory: path.join(buildFolder, 'Hekura-win32-x64'),
		outputDirectory: packageFolder,
		loadingGif: path.resolve(__dirname, './install-spinner.gif'),
		authors: signet.company,
		exe: signet.productName.toLowerCase() + '.exe',
		description: signet.productDescription,
		title: signet.productName,
		name : signet.productName,
		iconUrl: svcIconFile,
		setupIcon: svcIconFile,
		setupExe: 'install-' + signet.productName.toLowerCase() + '.exe',
		noMsi: true
	}

	let source;
	let entryPoint;
	let buildOptions;
	let excludeDirs;
	let packageOptions;
	let dependencies;
	switch (target) {
	case 'service':
		source = path.join(project, 'appservice');
		entryPoint = './appservice/main.js';
		buildOptions = svcBuildOptions;
		excludeDirs = svcExcludeDirs;
		packageOptions = svcPackageOptions;
		dependencies = svcDependencies;
		break;
	case 'app':
		throw new Error('--build=app not implemented yet');
		break;
	default: throw new Error('Invalid --build argument');
	}
	buildOptions.arch = arch;
	let msg = 'Build arguments:'
		.concat('\n--build: ').concat(target)
		.concat('\n--arch: ').concat(arch)
		.concat('\n--distribution: \n')
		.concat(JSON.stringify(signet, null, 2));
	console.log(msg);

	let distFile = path.join(source, 'distribution.json');
	let packageJSON = path.join(project, 'package.json');
	let backup = path.join(project, 'package-old.json');
	let version = getVersion(entryPoint);
	let pack;
	try { pack = JSON.parse(fs.readFileSync(packageJSON)); }
	catch(e) { throw new Error('Could not load package.json file: ' + e.toString()); }
	pack.name = signet.productName.toLowerCase();
	pack.version = version;
	pack.main = entryPoint;
	pack.dependencies = dependencies;
	pack.scripts = (function () { return; })();
	pack.gypfile = (function () { return; })();

	try { fs.writeFileSync(distFile, JSON.stringify(signet)); }
	catch(e) { throw new Error('Coult not generate signet file: ' + e.toString()); }
	try { fs.renameSync(packageJSON, backup); }
	catch(e) { throw new Error('Coult not create a package.json backup: ' + e.toString()); }
	try { fs.writeFileSync(packageJSON, JSON.stringify(pack)); }
	catch (e) { throw new Error('Coult not create proper package.json: ' + e.toString()); }

	msg = 'Standalone package will be built with the following definitions:'
		.concat('\ndirectories to exclude: ').concat(JSON.stringify(excludeDirs, null, 2))
		.concat('\nbuild options: ').concat(JSON.stringify(buildOptions, null, 2));
	console.log(msg);
	appPackage(buildOptions, excludeDirs).then((appPath) => {
		console.log('Package built to path: ' + appPath);
		packageOptions.appDirectory = appPath;
		msg = 'Application installer will be generated with the following definitions:\n'
			.concat(JSON.stringify(packageOptions, null, 2))
			.concat('\nIt may take a long, long, long time. Please, be patient...');
		console.log(msg);
		appInstaller(packageOptions).then(() => {
			console.log('Application installer has been built... at last!');
			fs.unlinkSync(packageJSON);
			fs.renameSync(backup, packageJSON);
		}).catch((reason) => {
			console.error(reason);
			fs.unlinkSync(packageJSON);
			fs.renameSync(backup, packageJSON);
		});
	}).catch((reason) => {
		console.error(reason);
		fs.unlinkSync(packageJSON);
		fs.renameSync(backup, packageJSON);
	});

}());
