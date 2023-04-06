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


const TARGET_SERVICE = 0;
const TARGET_APP = 1;
const BUILD_PACKAGE = 1;
const BUILD_INSTALLER = 2;
const BUILD_ALL = 3;
function getCmdLine() {
	const argv = yargs(process.argv).argv;
	let distFile = path.resolve(argv.distribution);
	let ret = {
		install: path.basename(distFile, '.distribution'),
		target: TARGET_SERVICE,
		signet: null,
		arch: 'x64',
		build: BUILD_ALL,
		verbose: false
	};
	switch (argv.target) {
	case 'service':
		break;
	case 'app':
		ret.target = TARGET_APP;
		throw new Error('--target=app not implemented yet');
	default:
		throw new Error('Invalid --target argument');
	}
	try { ret.signet = Distribution.load(distFile); }
	catch (e) { throw new Error('Argument --distribution must point to a valid Distribution JSON file: ' + e.toString()); }
	if (argv.arch === 'ia32') ret.arch = 'ia32';
	switch(argv.build) {
	case 'package':
		ret.build = BUILD_PACKAGE;
		break;
	case 'installer':
		ret.build = BUILD_INSTALLER;
		break;
	default:
	}
	if (argv.verbose) {
		ret.verbose = true;
		console.log(
			'Build arguments:'
			.concat('\n--target: ').concat(ret.target)
			.concat('\n--distribution: \n')
			.concat(JSON.stringify(ret.signet, null, 2))
			.concat('\n--arch: ').concat(ret.arch)
			.concat('\n--build: ').concat(ret.build)
			.concat('\n--verbose: ').concat(ret.verbose)		
		);
	}
	return ret;
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

function getServiceOptions(args) {
	const project = path.dirname(__dirname);
	const svcIconFile = path.join(project, 'appservice', 'res', 'signature-32x32.ico');
	const buildFolder = path.resolve(__dirname, 'output');
	const entryPoint = path.resolve('./appservice/main.js');
	const svcDependencies = {
		'alert': '^5.1.1',
		'asn1js': '^2.3.2',
		'node-addon-api': '^4.3.0'
	};
	const svcBuildOptions = {
		appCopyright: 'Copyleft (C) 2020-2023 The Crypthing Initiative. All rights reversed.',
		arch: args.arch,
		dir: project,
		executableName: args.signet.productName.toLowerCase(),
		icon: svcIconFile,
		ignore: [
			'.vscode/',
			'^/build/',
			'docs/',
			'hamahiri/',
			'lock/',
			'pki/',
			'signthing/',
			'test/',
			'web-api/',
			'.gitignore',
			'.jshintrc',
			'history.md',
			'LEIA-ME.MD',
			'package-lock.json',
			'package-old.json',
			'.*log',
			'TODO.txt'
		],
		name: args.signet.productName,
		out: buildFolder,
		overwrite: true,
		platform: 'win32',
		win32metadata: {
			CompanyName: args.signet.company,
			ProductName:  args.signet.productName,
			FileDescription: args.signet.productDescription
		}
	};
	const svcExcludeDirs = [ '.vscode', 'build', 'docs', 'hamahiri', 'lock', 'pki', 'signthing', 'test', 'web-api' ];
	const packageFolder = path.join(buildFolder, 'installer_' + args.install + '-' + getVersion(entryPoint));
	const svcPackageOptions = {
		appDirectory: path.join(buildFolder, args.signet.productName + '-win32-' + args.arch),
		outputDirectory: packageFolder,
		loadingGif: path.resolve(__dirname, args.signet.loadingGif),
		authors: args.signet.company,
		exe: args.signet.productName.toLowerCase() + '.exe',
		description: args.signet.productDescription,
		title: args.signet.productName,
		name : args.signet.productName,
		iconUrl: svcIconFile,
		setupIcon: svcIconFile,
		setupExe: 'install' + args.signet.productName.toLowerCase() + '.exe',
		noMsi: true
	};
	let ret = {
		home: project,
		source: path.join(project, 'appservice'),
		entryPoint: entryPoint,
		buildOptions: svcBuildOptions,
		excludeDirs: svcExcludeDirs,
		packageOptions: svcPackageOptions,
		dependencies: svcDependencies
	};
	if (args.verbose) {
		console.log(
			'Service options:\n'
			.concat('home: ').concat(ret.home).concat('\n')
			.concat('source: ').concat(ret.source).concat('\n')
			.concat('entryPoint: ').concat(ret.entryPoint).concat('\n')
			.concat('buildOptions: ').concat(JSON.stringify(ret.buildOptions, null, 2)).concat('\n')
			.concat('excludeDirs: ').concat(ret.excludeDirs).concat('\n')
			.concat('packageOptions: ').concat(JSON.stringify(ret.packageOptions, null, 2)).concat('\n')
			.concat('dependencies: ').concat(JSON.stringify(ret.dependencies, null, 2))
		);
	}
	return ret;
}

function getAppOptions(args) {
	// TODO:
	return null;
}

function generateNPMDescriptor(args, opts) {
	let packageJSON = path.join(opts.home, 'package.json');
	let backup = path.join(opts.home, 'package-old.json');
	let version = getVersion(opts.entryPoint);
	let pack;
	try { pack = JSON.parse(fs.readFileSync(packageJSON)); }
	catch(e) { throw new Error('Could not load package.json file: ' + e.toString()); }
	pack.name = args.signet.productName.toLowerCase();
	pack.version = version;
	pack.main = opts.entryPoint;
	pack.description = args.signet.productDescription;
	pack.dependencies = opts.dependencies;
	pack.scripts = (function () { return; })();
	pack.gypfile = (function () { return; })();
	try { fs.renameSync(packageJSON, backup); }
	catch(e) { throw new Error('Coult not create a package.json backup: ' + e.toString()); }
	try { fs.writeFileSync(packageJSON, JSON.stringify(pack)); }
	catch (e) { throw new Error('Coult not create proper package.json: ' + e.toString()); }
	if (args.verbose) console.log('The following package.json was generated: \n'.concat(JSON.stringify(pack, null, 2)));
	return { original: packageJSON, backup: backup };
}

function restoreNPMDescriptor(descriptor) {
	fs.unlinkSync(descriptor.original);
	fs.renameSync(descriptor.backup, descriptor.original);
}

function generateDistributionFile(args, target) {
	let distFile = path.join(target, 'distribution.json');
	try { fs.writeFileSync(distFile, JSON.stringify(args.signet)); }
	catch(e) { throw new Error('Coult not generate signet file: ' + e.toString()); }
	if (args.verbose) console.log('The following distribution file was generated: \n'.concat(JSON.stringify(args.signet, null, 2)));
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
 *  --target: string definindo a aplicação a ser construída, a saber: service | app. Obrigatório
 *  --distribution: caminho para o arquivo de configuração da distribuição. Obrigatório
 * 	--arch: string indicando a arquitetura de CPU alvo, a saber: x64 | ia32. Opcional. Default: x64
 *  --build: string definindo o tipo de construção, a saber: package | installer | all. Opcional. Default: all
 *  --verbose: indicador para a exibição em tela de todas as configurações utilizadas. Opcional
 */
(function () {

	let args = getCmdLine();
	let opts = args.target === TARGET_SERVICE ? getServiceOptions(args) : getAppOptions(args);
	let backup = generateNPMDescriptor(args, opts);

	if ((args.build & BUILD_PACKAGE) === BUILD_PACKAGE) {
		try { generateDistributionFile(args, opts.source); }
		catch (e) { 
			restoreNPMDescriptor(backup); 
			throw e;
		}
		console.log('Generating standalone package...');
		appPackage(opts.buildOptions, opts.excludeDirs)
		.then((appPath) => {
			console.log('Package built to path: ' + appPath);
			restoreNPMDescriptor(backup);
			if (args.build === BUILD_ALL) {
				console.log('Generating install package. It may take a long, long, long time. Please, be patient...');
				appInstaller(opts.packageOptions)
					.then(() => { console.log('Application installer has been built... at last!');})
					.catch((reason) => { console.error(reason); });
			}
		}).catch((reason) => {
			console.log(reason);
			restoreNPMDescriptor(backup);
		});
	}

	if ((args.build & BUILD_INSTALLER) === BUILD_INSTALLER && args.build !== BUILD_ALL) {
		try { generateDistributionFile(args, path.join(opts.packageOptions.appDirectory, 'resources', 'app', 'appservice')); }
		catch (e) { 
			restoreNPMDescriptor(backup); 
			throw e;
		}
		restoreNPMDescriptor(backup);
		console.log('Generating install package. It may take a long, long, long time. Please, be patient...');
		appInstaller(opts.packageOptions)
			.then(() => { console.log('Application installer has been built... at last!');})
			.catch((reason) => { console.error(reason); });
	}

}());
